/*
 * Copyright (C) 2009 Emweb bvba, Kessel-Lo, Belgium.
 *
 * See the LICENSE file for terms of use.
 */

// bugfix for https://svn.boost.org/trac/boost/ticket/5722
#include <boost/asio.hpp>

#include "Wt/Http/Client"
#include "Wt/WApplication"
#include "Wt/WEnvironment"
#include "Wt/WLogger"
#include "Wt/WServer"
#include "Wt/Utils"
#include "Wt/WIOService"

#include <sstream>
#include <boost/lexical_cast.hpp>
#include <boost/system/error_code.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>

#ifdef WT_WITH_SSL
#include <boost/asio/ssl.hpp>

#if BOOST_VERSION >= 104700
#define VERIFY_CERTIFICATE
#endif

#endif // WT_WITH_SSL

#ifdef WT_WIN32
#define strcasecmp _stricmp
#endif

using boost::asio::ip::tcp;

#if BOOST_VERSION >= 104900 && defined(BOOST_ASIO_HAS_STD_CHRONO)
#include <boost/asio/steady_timer.hpp>
typedef boost::asio::steady_timer asio_timer;
typedef std::chrono::seconds asio_timer_seconds;
#else
typedef boost::asio::deadline_timer asio_timer;
typedef boost::posix_time::seconds asio_timer_seconds;
#endif

namespace Wt {

LOGGER("Http.Client");

  namespace Http {

#ifdef WT_WITH_SSL
        struct ssl_context
        {
            boost::asio::ssl::context context_;
            bool verifyEnabled_;
            ssl_context(boost::asio::io_service & ioService);
            void set_verification_options(
                const std::string & verifyFile,
                const std::string & verifyPath,
                bool verifyEnabled);
        };
#endif // WT_WITH_SSL

        struct backend_arg
        {
            std::string sessionId_;
            boost::asio::io_service * ioService_;
            WServer * server_;
            Client::URL parsedUrl_;

            backend_arg(boost::asio::io_service * ioService, const std::string & url);
            bool is_http_scheme() const;
            bool is_https_scheme() const;
            bool valid_protocol() const;
            ssl_context make_ssl_context();
        };

        bool parseUrl(const std::string & url, Client::URL & parsedUrl);

class Client::Impl : public boost::enable_shared_from_this<Client::Impl>
{
public:
  Impl(boost::asio::io_service& ioService, WServer *server,
       const std::string& sessionId)
    : ioService_(ioService),
      strand_(ioService),
      resolver_(ioService_),
      timer_(ioService_),
      server_(server),
      sessionId_(sessionId),
      timeout_(0),
      maximumResponseSize_(0),
      responseSize_(0),
      aborted_(false)
      , decoder_(response_)
  { }

  virtual ~Impl() { }

  void setTimeout(int timeout) {
    timeout_ = timeout;
  }

  void setMaximumResponseSize(std::size_t bytes) {
    maximumResponseSize_ = bytes;
    decoder_.setMaximumResponseSize(bytes);
  }

  void request(const std::string & method, const URL & parsedUrl, const Message & message)
  {
      // push the wire encoding into write buffer
      std::ostream out(&requestBuf_);
      http_wire_encoder encoder(method,parsedUrl,message);
      encoder.stream_out_request(out);
      // start dns resolution
      request(method,
              parsedUrl.protocol,
              parsedUrl.auth,
              parsedUrl.host,
              parsedUrl.port,
              parsedUrl.path,
              message);
  }

  void request(const std::string& method, const std::string& protocol, const std::string& auth,
	       const std::string& server, int port, const std::string& path,
	       const Message& message)
  {
    tcp::resolver::query query(server, boost::lexical_cast<std::string>(port));

    startTimer();
    resolver_.async_resolve
      (query,
       strand_.wrap(boost::bind(&Impl::handleResolve,
				shared_from_this(),
				boost::asio::placeholders::error,
				boost::asio::placeholders::iterator)));
  }

  void asyncStop(boost::shared_ptr<Impl> *impl)
  {
    ioService_.post
      (strand_.wrap(boost::bind(&Impl::stop, shared_from_this(), impl)));
  }

  Signal<boost::system::error_code, Message>& done() { return done_; }
  Signal<Message>& headersReceived() { return headersReceived_; }
  Signal<std::string>& bodyDataReceived() { return bodyDataReceived_; }

  bool hasServer() { return server_ != 0; }

protected:
  typedef boost::function<void(const boost::system::error_code&)>
    ConnectHandler;
  typedef boost::function<void(const boost::system::error_code&,
			       const std::size_t&)> IOHandler;

  virtual tcp::socket& socket() = 0;
  virtual void asyncConnect(tcp::endpoint& endpoint,
			    const ConnectHandler& handler) = 0;
  virtual void asyncHandshake(const ConnectHandler& handler) = 0;
  virtual void asyncWriteRequest(const IOHandler& handler) = 0;
  virtual void asyncReadUntil(const std::string& s,
			      const IOHandler& handler) = 0;
  virtual void asyncRead(const IOHandler& handler) = 0;

private:
  void stop(boost::shared_ptr<Impl> *impl)
  {
    /* Within strand */

    aborted_ = true;

    try {
      if (socket().is_open()) {
	boost::system::error_code ignored_ec;
	socket().shutdown(tcp::socket::shutdown_both, ignored_ec);
	socket().close();
      }
    } catch (std::exception& e) {
      LOG_INFO("Client::abort(), stop(), ignoring error: " << e.what());
    }

    if (impl)
      impl->reset();
  }

  void startTimer()
  {
    timer_.expires_from_now(asio_timer_seconds(timeout_));
    timer_.async_wait
      (strand_.wrap(boost::bind(&Impl::timeout, shared_from_this(),
				boost::asio::placeholders::error)));
  }

  void cancelTimer()
  {
    /* Within strand */

    timer_.cancel();
  }

  void timeout(const boost::system::error_code& e)
  {
    /* Within strand */

    if (e != boost::asio::error::operation_aborted) {
      boost::system::error_code ignored_ec;
      socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both,
			ignored_ec);

      err_ = boost::asio::error::timed_out;
    }
  }

  void handleResolve(const boost::system::error_code& err,
		     tcp::resolver::iterator endpoint_iterator)
  {
    /* Within strand */

    cancelTimer();

    if (!err && !aborted_) {
      // Attempt a connection to the first endpoint in the list.
      // Each endpoint will be tried until we successfully establish
      // a connection.
      tcp::endpoint endpoint = *endpoint_iterator;

      startTimer();
      asyncConnect(endpoint,
		   strand_.wrap(boost::bind(&Impl::handleConnect,
					    shared_from_this(),
					    boost::asio::placeholders::error,
					    ++endpoint_iterator)));
    } else {
      err_ = err;
      complete();
    }
  }

  void handleConnect(const boost::system::error_code& err,
		     tcp::resolver::iterator endpoint_iterator)
  {
    /* Within strand */

    cancelTimer();

    if (!err && !aborted_) {
      // The connection was successful. Do the handshake (SSL only)
      startTimer();
      asyncHandshake
	(strand_.wrap(boost::bind(&Impl::handleHandshake,
				  shared_from_this(),
				  boost::asio::placeholders::error)));
    } else if (endpoint_iterator != tcp::resolver::iterator()) {
      // The connection failed. Try the next endpoint in the list.
      socket().close();

      handleResolve(boost::system::error_code(), endpoint_iterator);
    } else {
      err_ = err;
      complete();
    }
  }

  void handleHandshake(const boost::system::error_code& err)
  {
    /* Within strand */

    cancelTimer();

    if (!err && !aborted_) {
      // The handshake was successful. Send the request.
      startTimer();
      asyncWriteRequest
	(strand_.wrap
	 (boost::bind(&Impl::handleWriteRequest,
		      shared_from_this(),
		      boost::asio::placeholders::error,
		      boost::asio::placeholders::bytes_transferred)));
    } else {
      err_ = err;
      complete();
    }
  }

  void handleWriteRequest(const boost::system::error_code& err,
			  const std::size_t&)
  {
    /* Within strand */

    cancelTimer();

    if (!err) {
      // Read the response status line.
      startTimer();
      asyncReadUntil
	("\r\n",
	 strand_.wrap
	 (boost::bind(&Impl::handleReadStatusLine,
		      shared_from_this(),
		      boost::asio::placeholders::error,
		      boost::asio::placeholders::bytes_transferred)));
    } else {
      err_ = err;
      complete();
    }
  }

  bool addResponseSize(std::size_t s)
  {
    responseSize_ += s;

    if (maximumResponseSize_ && responseSize_ > maximumResponseSize_) {
      err_ = boost::asio::error::message_size;
      complete();
      return false;
    }

    return true;
  }

  void handleReadStatusLine(const boost::system::error_code& err,
			    const std::size_t& s)
  {
    /* Within strand */

    cancelTimer();

    if (!err) {
      if (!addResponseSize(s))
	return;

      // Check that response is OK.
      std::istream response_stream(&responseBuf_);
      if(!decoder_.parse_status_line(response_stream)) {
	err_ = boost::system::errc::make_error_code
	  (boost::system::errc::protocol_error);
	complete();
	return;
      }
      // Read the response headers, which are terminated by a blank line.
      startTimer();
      asyncReadUntil
	("\r\n\r\n",
	 strand_.wrap
	 (boost::bind(&Impl::handleReadHeaders,
		      shared_from_this(),
		      boost::asio::placeholders::error,
		      boost::asio::placeholders::bytes_transferred)));
    } else {
      err_ = err;
      complete();
    }
  }

  void handleReadHeaders(const boost::system::error_code& err,
			 const std::size_t& s)
  {
    /* Within strand */

    cancelTimer();

    if (!err) {
      if (!addResponseSize(s))
	return;



      // Process the response headers.
      std::istream response_stream(&responseBuf_);
      decoder_.parse_response_headers(response_stream);

      if (headersReceived_.isConnected()) {
	if (server_)
	  server_->post(sessionId_,
			boost::bind(&Impl::emitHeadersReceived,
				    shared_from_this()));
	else
	  emitHeadersReceived();
      }

      // Write whatever content we already have to output.
      if (responseBuf_.size() > 0) {
	std::stringstream ss;
	ss << &responseBuf_;
	addBodyText(ss.str());
      }

      if (!aborted_) {
        // Start reading remaining data until EOF.
        startTimer();
        asyncRead(strand_.wrap
                  (boost::bind(&Impl::handleReadContent,
                               shared_from_this(),
                               boost::asio::placeholders::error,
                               boost::asio::placeholders::bytes_transferred)));
      }
    } else {
      err_ = err;
      complete();
    }
  }

  void handleReadContent(const boost::system::error_code& err,
          const std::size_t& s)
  {
    /* Within strand */

    cancelTimer();

    if (!err) {
      if (!addResponseSize(s))
	return;

      std::stringstream ss;
      ss << &responseBuf_;

      addBodyText(ss.str());

      if (!aborted_) {
	// Continue reading remaining data until EOF.
	startTimer();
	asyncRead
	  (strand_.wrap
	   (boost::bind(&Impl::handleReadContent,
			shared_from_this(),
			boost::asio::placeholders::error,
			boost::asio::placeholders::bytes_transferred)));
      }
    } else if (err != boost::asio::error::eof
	       && err != boost::asio::error::shut_down
	       && err != boost::asio::error::bad_descriptor
	       && err != boost::asio::error::operation_aborted
	       && err.value() != 335544539) {
      err_ = err;
      complete();
    } else {
      complete();
    }
  }

  void addBodyText(const std::string & text)
  {
      // Write whatever content we already have to output.
      std::string data;
      std::istream response_stream(&responseBuf_);
      if(!decoder_.parse_response_payload(response_stream,data))
      {
          LOG_INFO("Protocol Error: line '" << __LINE__ << "'");
          protocolError(decoder_.error());
          return;
      }
      if(!decoder_.is_done())
      {
          LOG_INFO("haveBodyData: line '" << __LINE__ << "'");
          haveBodyData(data);
      }
      else
      {
          LOG_INFO("Complete: line '" << __LINE__ << "'");
          protocolError(boost::system::errc::make_error_code(boost::system::errc::success));
          return;
      }
      if(!aborted_)
      {
          // Continue reading remaining data until EOF.
          startTimer();
          asyncRead(
                  strand_.wrap(boost::bind(&Impl::handleReadContent, shared_from_this(),
                          boost::asio::placeholders::error,
                          boost::asio::placeholders::bytes_transferred)));
      }
  }

  void protocolError(const boost::system::error_code& err)
  {
      // explictly filter protocol errors
      if(err == boost::asio::error::eof
              || err == boost::asio::error::shut_down
              || err == boost::asio::error::bad_descriptor
              || err == boost::asio::error::operation_aborted
              || err.value() == 335544539)
      {
          err_ = decoder_.error();
      }
      else
      {
          err_ = err;
      }
      complete();
  }

  void complete()
  {
      stop(0);
      haveBodyEOF();
  }

  void haveHeaderData()
  {
      if(headersReceived_.isConnected())
      {
          if(server_)
          {
              server_->post(sessionId_,
                      boost::bind(&Impl::emitHeadersReceived, shared_from_this()));
          }
          else
          {
              emitHeadersReceived();
          }
      }
  }

  void haveBodyData(const std::string& text)
  {
      if(bodyDataReceived_.isConnected())
      {
          if(server_)
          {
              server_->post(sessionId_,
                      boost::bind(&Impl::emitBodyReceived, shared_from_this(), text));
          }
          else
          {
              emitBodyReceived(text);
          }
      }
  }

  void haveBodyEOF()
  {
      if(server_)
      {
          server_->post(sessionId_,
                  boost::bind(&Impl::emitDone, shared_from_this()));
      }
      else
      {
          emitDone();
      }
  }

  void emitDone()
  {
      done_.emit(err_, response_);
  }

  void emitHeadersReceived()
  {
      headersReceived_.emit(response_);
  }

  void emitBodyReceived(const std::string& text)
  {
      bodyDataReceived_.emit(text);
  }

protected:
  boost::asio::io_service& ioService_;
  boost::asio::strand strand_;
  tcp::resolver resolver_;
  boost::asio::streambuf requestBuf_;
  boost::asio::streambuf responseBuf_;

private:
  asio_timer timer_;
  WServer * server_;
  std::string sessionId_;
  int timeout_;
  std::size_t maximumResponseSize_, responseSize_;
  boost::system::error_code err_;
  Message response_;
  http_wire_decoder decoder_;
  Signal<boost::system::error_code, Message> done_;
  Signal<Message> headersReceived_;
  Signal<std::string> bodyDataReceived_;
  bool aborted_;
};

class Client::TcpImpl
: public Client::Impl
{
    public:
        TcpImpl(boost::asio::io_service& ioService, WServer * server, const std::string& sessionId)
            : Impl(ioService, server, sessionId)
              , socket_(ioService_)
    { }

    protected:
        virtual tcp::socket& socket()
        {
            return socket_;
        }

        virtual void asyncConnect(tcp::endpoint& endpoint, const ConnectHandler& handler)
        {
            socket_.async_connect(endpoint, handler);
        }

        virtual void asyncHandshake(const ConnectHandler& handler)
        {
            handler(boost::system::error_code());
        }

        virtual void asyncWriteRequest(const IOHandler& handler)
        {
            boost::asio::async_write(socket_, requestBuf_, handler);
        }

        virtual void asyncReadUntil(const std::string& s, const IOHandler& handler)
        {
            boost::asio::async_read_until(socket_, responseBuf_, s, handler);
        }

        virtual void asyncRead(const IOHandler& handler)
        {
            boost::asio::async_read(socket_, responseBuf_,
                    boost::asio::transfer_at_least(1), handler);
        }

    private:
        tcp::socket socket_;
};

#ifdef WT_WITH_SSL

class Client::SslImpl
: public Client::Impl
{
    public:
        SslImpl(boost::asio::io_service& ioService, bool verifyEnabled, WServer * server,
                boost::asio::ssl::context& context, const std::string& sessionId, const std::string& hostName)
            : Impl(ioService, server, sessionId),
            socket_(ioService_, context),
            verifyEnabled_(verifyEnabled),
            hostName_(hostName)
    {
#ifndef OPENSSL_NO_TLSEXT
        if(!SSL_set_tlsext_host_name(socket_.native_handle(), hostName.c_str()))
        {
            LOG_ERROR("could not set tlsext host.");
        }
#endif
    }

    protected:
        virtual tcp::socket& socket()
        {
            return socket_.next_layer();
        }

        virtual void asyncConnect(tcp::endpoint& endpoint, const ConnectHandler& handler)
        {
            socket_.lowest_layer().async_connect(endpoint, handler);
        }

        virtual void asyncHandshake(const ConnectHandler& handler)
        {
#ifdef VERIFY_CERTIFICATE
            if(verifyEnabled_)
            {
                socket_.set_verify_mode(boost::asio::ssl::verify_peer);
                LOG_DEBUG("verifying that peer is " << hostName_);
                socket_.set_verify_callback(boost::asio::ssl::rfc2818_verification(hostName_));
            }
#endif // VERIFY_CERTIFICATE
            socket_.async_handshake(boost::asio::ssl::stream_base::client, handler);
        }

        virtual void asyncWriteRequest(const IOHandler& handler)
        {
            boost::asio::async_write(socket_, requestBuf_, handler);
        }

        virtual void asyncReadUntil(const std::string& s,
                const IOHandler& handler)
        {
            boost::asio::async_read_until(socket_, responseBuf_, s, handler);
        }

        virtual void asyncRead(const IOHandler& handler)
        {
            boost::asio::async_read(socket_, responseBuf_,
                    boost::asio::transfer_at_least(1), handler);
        }

    private:
        typedef boost::asio::ssl::stream<tcp::socket> ssl_socket;

        ssl_socket socket_;
        bool verifyEnabled_;
        std::string hostName_;
};
#endif // WT_WITH_SSL

Client::Client(WObject * parent)
    : WObject(parent),
    ioService_(0),
    timeout_(10),
    maximumResponseSize_(64*1024),
#ifdef VERIFY_CERTIFICATE
    verifyEnabled_(true),
#else
    verifyEnabled_(false),
#endif
    followRedirect_(false),
    redirectCount_(0),
    maxRedirects_(20)
{ }

Client::Client(boost::asio::io_service& ioService, WObject * parent)
    : WObject(parent),
    ioService_(&ioService),
    timeout_(10),
    maximumResponseSize_(64*1024),
#ifdef VERIFY_CERTIFICATE
    verifyEnabled_(true),
#else
    verifyEnabled_(false),
#endif
    followRedirect_(false),
    redirectCount_(0),
    maxRedirects_(20)
{ }

Client::~Client()
{
    abort();
}

void Client::setSslCertificateVerificationEnabled(bool enabled)
{
    verifyEnabled_ = enabled;
}

void Client::abort()
{
    boost::shared_ptr<Impl> impl = impl_;
    if(impl)
    {
        if(impl->hasServer())
        {
            // handling of redirect happens in the WApplication
            impl->asyncStop(0);
            impl_.reset();
        }
        else
        {
            // handling of redirect happens in the strand of impl
            impl->asyncStop(&impl_);
        }
    }
}

void Client::setTimeout(int seconds)
{
    timeout_ = seconds;
}

void Client::setMaximumResponseSize(std::size_t bytes)
{
    maximumResponseSize_ = bytes;
}

void Client::setSslVerifyFile(const std::string& file)
{
    verifyFile_ = file;
}

void Client::setSslVerifyPath(const std::string& path)
{
    verifyPath_ = path;
}

bool Client::get(const std::string& url)
{
    return request(Get, url, Message());
}

bool Client::get(const std::string& url,
        const std::vector<Message::Header>& headers)
{
    Message m(headers);
    return request(Get, url, m);
}

bool Client::post(const std::string& url, const Message& message)
{
    return request(Post, url, message);
}

bool Client::put(const std::string& url, const Message& message)
{
    return request(Put, url, message);
}

bool Client::deleteRequest(const std::string& url, const Message& message)
{
    return request(Delete, url, message);
}

bool Client::patch(const std::string& url, const Message& message)
{
    return request(Patch, url, message);
}

bool Client::request(Http::Method method, const std::string& url,
        const Message& message)
{
    if(impl_.get())
    {
        LOG_ERROR("another request is in progress");
        return false;
    }
    std::unique_ptr<backend_arg> arg;
    try
    {
        arg.reset(new Http::backend_arg(ioService_,url));
        if(arg->is_http_scheme())
        {
            impl_.reset(new Client::TcpImpl(*arg->ioService_, arg->server_, arg->sessionId_));
#ifdef WT_WITH_SSL
        }
        else if(arg->is_https_scheme())
        {
            auto context = arg->make_ssl_context();
#ifdef VERIFY_CERTIFICATE
            context.set_verification_options(verifyFile_,verifyPath_,verifyEnabled_);
#endif // VERIFY_CERTIFICATE
            impl_.reset(new Client::SslImpl(*arg->ioService_, verifyEnabled_, arg->server_, context.context_, arg->sessionId_, arg->parsedUrl_.host));
#endif // WT_WITH_SSL
        }
        if(followRedirect())
        {
            impl_->done().connect(boost::bind(&Client::handleRedirect, this, method, _1, _2, message));
        }
        else
        {
            impl_->done().connect(this, &Client::emitDone);
        }
        if(headersReceived_.isConnected())
        {
            impl_->headersReceived().connect(this, &Client::emitHeadersReceived);
        }
        if(bodyDataReceived_.isConnected())
        {
            impl_->bodyDataReceived().connect(this, &Client::emitBodyReceived);
        }
        impl_->setTimeout(timeout_);
        impl_->setMaximumResponseSize(maximumResponseSize_);
        const char * methodNames_[] = { "GET", "POST", "PUT", "DELETE", "PATCH" };
        LOG_DEBUG(methodNames_[method] << " " << url);
        impl_->request(methodNames_[method],arg->parsedUrl_, message);
        return true;
    }
    catch(std::runtime_error& err)
    {
        LOG_ERROR(err.what());
    }
    return false;
}

bool Client::followRedirect() const
{
    return followRedirect_;
}

void Client::setFollowRedirect(bool followRedirect)
{
    followRedirect_ = followRedirect;
}

int Client::maxRedirects() const
{
    return maxRedirects_;
}

void Client::setMaxRedirects(int maxRedirects)
{
    maxRedirects_ = maxRedirects;
}

// 301 Moved Permanently  = new request with same method if idomponent or rewritten to GET otherwise
// 302 Found              = new request with same method if idomponent or rewritten to GET otherwise
// 303 See Other          = new request with GET method
// 307 Temporary Redirect = new request with same method / body
// 308 Permanent Redirect = new request with same method / body

void Client::handleRedirect(Http::Method method,
        boost::system::error_code err, const Message& response, const Message& request)
{
    if(!impl_)
    {
        emitDone(err, response);
        return;
    }
    impl_.reset();
    int status = response.status();
    if(!err && (status == 301 || status == 302 || status == 303 || status == 307 || status == 308))
    {
        if(status == 303 || (status < 307 && (method == Put || method == Patch || method == Delete || method == Post)))
        {
            method = Get;
        }
        const std::string * newUrl = response.getHeader("Location");
        ++ redirectCount_;
        if(newUrl && redirectCount_ <= maxRedirects_)
        {
            this->request(method, *newUrl, request);
            return;
        }
        if(!newUrl)
        {
            LOG_WARN("No 'Location' header for redirect : " << redirectCount_ << " redirects");
        }
        else
        {
            LOG_WARN("Redirect count of " << maxRedirects_ << " exceeded! Redirect URL: " << *newUrl);
        }
    }
    emitDone(err, response);
}

void Client::emitDone(boost::system::error_code err, const Message& response)
{
    impl_.reset();
    redirectCount_ = 0;
    done_.emit(err, response);
}

void Client::emitHeadersReceived(const Message& response)
{
    headersReceived_.emit(response);
}

void Client::emitBodyReceived(const std::string& data)
{
    bodyDataReceived_.emit(data);
}

bool Client::parseUrl(const std::string& url, URL& parsedUrl)
{
    return Http::parseUrl(url,parsedUrl);
}

http_wire_decoder::http_wire_decoder(Message& m)
    : message_{m}
    , chunkState_{}
    , http_version_{}
    , status_message_{}
    , maximumResponseSize_{0}
    , status_code_{}
    , valid_{false}
    , done_{false}
{}

void http_wire_decoder::setMaximumResponseSize(std::size_t bytes)
{
    maximumResponseSize_ = bytes;
}

bool http_wire_decoder::is_valid() const
{
    return valid_;
}

bool http_wire_decoder::is_done() const
{
    return done_;
}

boost::system::error_code http_wire_decoder::error() const
{
    return boost::system::errc::make_error_code(boost::system::errc::protocol_error);
}

bool http_wire_decoder::parse_status_line(std::istream& response_stream)
{
    static constexpr const char * http_slash_str = "HTTP/";
    static constexpr const size_t http_slash_sz  = std::strlen(http_slash_str);
    valid_ = (response_stream >> http_version_
            && response_stream >> status_code_
            && std::getline(response_stream, status_message_)
            && http_version_.substr(0, http_slash_sz) == http_slash_str);
    if(valid_)
    {
        // strip "http/"
        http_version_.erase(0,5);
        // require terminating carriage return
        auto sz = status_message_.find_last_of("\r");
        valid_  = (sz != std::string::npos);
        if(valid_)
        {
            status_message_.erase(sz);
            status_message_ = boost::trim_copy(status_message_);
        }

        LOG_DEBUG(status_code_ << " " << status_message_);
        message_.setStatus(status_code_);
    }
    return valid_;
}

bool http_wire_decoder::parse_response_headers(std::istream& response_stream)
{
    LOG_INFO(__func__ << ": line '" << __LINE__ << "'");
    if(!valid_)
    {
        LOG_INFO("Protocol Error: line '" << __LINE__ << "'");
        return false;
    }
    // Process the response headers.
    std::string header;
    while(std::getline(response_stream, header) && header != "\r")
    {
        std::size_t i = header.find(':');
        if(i != std::string::npos)
        {
            std::string name = boost::trim_copy(header.substr(0, i));
            std::string value = boost::trim_copy(header.substr(i+1));
            message_.addHeader(name, value);
            if(boost::iequals(name, "Transfer-Encoding") && boost::iequals(value, "chunked"))
            {
                LOG_INFO("Chunked Transfer Encoding");
                chunkState_.reset(new ChunkState);
            }
        }
    }
    return true;
}

bool http_wire_decoder::parse_response_payload(std::istream& response_stream,std::string& data)
{
    LOG_INFO(__func__ << ": line '" << __LINE__ << "'");
    std::stringstream ss;
    valid_ = (valid_ && response_stream && ss << response_stream.rdbuf());
    if(!valid_)
    {
        LOG_INFO("Protocol Error: line '" << __LINE__ << "'");

        // protocol error
        done_ = true;
        return false;
    }
    data = ss.str();
    if(!chunkState_)
    {
        LOG_INFO(__func__ << ": line '" << __LINE__ << "'");
        valid_ = done_  = !data.empty();
        if(valid_)
        {
            LOG_INFO("Data: '" << data << "'");
            if(maximumResponseSize_)
            {
                message_.addBodyText(data);
            }
        }
    }
    else
    {
        LOG_INFO("Chunked Data: '" << data << "'");
        chunkState_->refill(data);
        valid_ = chunkState_->next_chunk(data);
        done_  = chunkState_->is_done();
        if(!done_ && valid_)
        {
            LOG_INFO("Unchunked Data: '" << data << "'");
            if(maximumResponseSize_)
            {
                message_.addBodyText(data);
            }
        }
    }
    return valid_;
}

ChunkState::ChunkState()
    :state_{ChunkState::Size}
    ,size_{}
    ,parsePos_{}
    , data_{}
    , pos_{data_.end()}
    , end_{data_.end()}
    , valid_{false}
    , done_{false}

{
}

bool ChunkState::is_done() const
{
    return done_;
}

bool ChunkState::is_valid() const
{
    return valid_;
}

bool ChunkState::empty() const
{
    return (pos_ == end_);
}

void ChunkState::refill(const std::string& data)
{
    data_ = data;
    pos_ = data_.begin();
    end_ = data_.end();
}

bool ChunkState::matched_hex_digit(int ch)
{
    static constexpr const unsigned char digits_l[] = { '0','a','A'};
    static constexpr const unsigned char digits_r[] = { '9','f','F'};
    static constexpr const unsigned char addend[]   = {  0,  10, 10};
    for(int idx=0; idx != (sizeof(digits_l)/sizeof(digits_l[0])); ++idx)
    {
        valid_ = (ch >= digits_l[idx] && ch <= digits_r[idx]);
        if(!valid_)
        {
            continue;
        }
        // decode hex digits
        size_ << 4;
        size_ |= ((addend[idx]+ch) - digits_l[idx]);
        break;
    }
    return valid_;
}

bool ChunkState::matched_delimiter(int ch)
{
    /* Ignoring extensions and syntax for now */
    static constexpr const int delimiters[] = {  '\r', ';'};
    static constexpr const int trailing_pos[] = {  2, 1};
    for(int idx=0; idx != (sizeof(delimiters)/sizeof(delimiters[0])); ++idx)
    {
        valid_ = (ch == delimiters[idx]);
        if(!valid_)
        {
            continue;
        }
        parsePos_ = trailing_pos[idx];
        break;
    }
    return valid_;
}

bool ChunkState::matched_size_ch(int ch)
{
    static constexpr const int leading_pos[] = { -1, 0 };
    static constexpr const int alphabet[] = { '\r', '\n'};
    static constexpr const int leading[] = { -2, -1 };
    switch(parsePos_)
    {
        // handle leading delimiters
        case -2: // fall through
        case -1: // fall through
            valid_ = (ch == alphabet[2+parsePos_]);
            parsePos_ = (valid_) ?  leading_pos[2+parsePos_] : parsePos_;
            state_    = (valid_) ?  state_ : ChunkState::Error;
            break;
        case 0:
            /* Ignoring extensions and syntax for now */
            valid_ = (matched_hex_digit(ch) || (matched_delimiter(ch)));
            state_ = (valid_) ? state_ : ChunkState::Error;
            break;
            // handle trailing delimiters
        case 1:
            parsePos_ = (ch == '\r') + 1 ;
            valid_ = parsePos_;
            break;
        case 2:
            valid_ = (ch == '\n');
            state_ = ChunkState::Error;
            if(valid_)
            {
                state_ = (size_ == 0) ? ChunkState::Complete : ChunkState::Data;
                done_  = (size_ == 0) ;
            }
            break;
    }
    return valid_;
}

bool ChunkState::next_chunk(std::string& data)
{
    size_t thisChunk=0;
    while(pos_ != end_)
    {
        switch(state_)
        {
            case ChunkState::Size:
                matched_size_ch(*(pos_++));
                break;
            case ChunkState::Data:
                data = current_chunk();
                thisChunk = current_chunk_size();
                pos_ += thisChunk;
                size_ -= thisChunk;
                parsePos_ = (size_ == 0) ? -2 : parsePos_;
                state_ = (size_ == 0) ? ChunkState::Size : state_;
                valid_ = true;
                done_  = false;
                break;
            case ChunkState::Complete:
                done_ = true;
                valid_= true;
                break;
            case ChunkState::Error:
                done_ = true;
                valid_= false;
        }
    }
    return valid_;
}

std::size_t ChunkState::current_chunk_size() const
{
    // limit copied length to what we have rather then what server claims
    return std::min(std::size_t(end_ - pos_), size_);
}

std::string ChunkState::current_chunk() const
{
    return std::string(pos_, pos_ + current_chunk_size());
}

http_wire_encoder::http_wire_encoder(const std::string& meth, const Client::URL& parsedUrl, const Message& m)
    : method_{meth}
    , protocol_{parsedUrl.protocol}
    , auth_{parsedUrl.auth}
    , server_{parsedUrl.host}
    , port_{parsedUrl.port}
    , path_{parsedUrl.path}
    , message_{m}
{}

std::ostream& http_wire_encoder::stream_out_request(std::ostream& request_stream)
{
    request_stream
        << method_ << " " << path_ << " HTTP/1.1\r\n";
    if((protocol_ == "http" && port_ == 80) || (protocol_ == "https" && port_ == 443))
    {
        request_stream
            << "Host: " << server_ << "\r\n";
    }
    else
        request_stream
            << "Host: " << server_ << ":" << boost::lexical_cast<std::string>(port_) << "\r\n";
    if(!auth_.empty())
    {
        request_stream
            << "Authorization: Basic " << Wt::Utils::base64Encode(auth_) << "\r\n";
    }
    bool haveContentLength = false;
    for(unsigned i = 0; i < message_.headers().size(); ++i)
    {
        const Message::Header& h = message_.headers()[i];
        if(strcasecmp(h.name().c_str(), "Content-Length") == 0)
        {
            haveContentLength = true;
        }
        request_stream
            << h.name() << ": " << h.value() << "\r\n";
    }
    if((method_ == "POST"
                || method_ == "PUT"
                || method_ == "DELETE"
                || method_ == "PATCH") && !haveContentLength)
    {
        request_stream
            << "Content-Length: " << message_.body().length() << "\r\n";
    }
    request_stream
        << "Connection: close\r\n\r\n";
    if(method_ == "POST" || method_ == "PUT" || method_ == "DELETE" || method_ == "PATCH")
    {
        request_stream << message_.body();
    }
    return request_stream;
}
#ifdef WT_WITH_SSL
ssl_context::ssl_context(boost::asio::io_service& ioService)
    : context_{ioService, boost::asio::ssl::context::sslv23}
    , verifyEnabled_{false}
{
    context_.set_options(boost::asio::ssl::context::no_sslv2 | boost::asio::ssl::context::no_sslv3);
}

void ssl_context::set_verification_options(const std::string& verifyFile, const std::string& verifyPath, bool verifyEnabled)
{
#ifdef VERIFY_CERTIFICATE
    verifyEnabled_ = verifyEnabled;
    if(verifyEnabled)
    {
        context_.set_default_verify_paths();
    }
    if(!verifyFile.empty())
    {
        context_.load_verify_file(verifyFile);
    }
    if(!verifyPath.empty())
    {
        context_.add_verify_path(verifyPath);
    }
#endif // VERIFY_CERTIFICATE
}
#endif // WT_WITH_SSL
backend_arg::backend_arg(boost::asio::io_service * ioService, const std::string& url)
    : ioService_{ioService}
    , server_{nullptr}
{
    WApplication * app = WApplication::instance();
    if(app && !ioService)
    {
        sessionId_ = app->sessionId();
        server_ = app->environment().server();
        ioService_ = &server_->ioService();
    }
    else if(!ioService)
    {
        server_ = WServer::instance();
        if(server_)
        {
            ioService_ = &server_->ioService();
            server_ = nullptr;
        }
        else
        {
            throw std::runtime_error("requires a WIOService for async I/O");
        }
    }
    if(!Http::parseUrl(url, parsedUrl_) || !valid_protocol())
    {
        throw std::runtime_error("parsing url failed: " + url);
    }
}
bool backend_arg::is_http_scheme() const
{
    return (parsedUrl_.protocol == "http");
}

bool backend_arg::is_https_scheme() const
{
    return (parsedUrl_.protocol == "https");
}

bool backend_arg::valid_protocol() const
{
    if(is_http_scheme())
    {
        return true;
#ifdef WT_WITH_SSL
    }
    else if(is_https_scheme())
    {
        return true;
#endif // WT_WITH_SSL
    }
    LOG_ERROR("unsupported protocol: " << parsedUrl_.protocol);
    return false;
}

ssl_context backend_arg::make_ssl_context()
{
    ssl_context context(*ioService_);
    return context;
}

bool parseUrl(const std::string& url, Client::URL& parsedUrl)
{
    std::size_t i = url.find("://");
    if(i == std::string::npos)
    {
        LOG_ERROR("ill-formed URL: " << url);
        return false;
    }
    // protocol will not be handled anyway
    parsedUrl.port = 80;
    parsedUrl.protocol = url.substr(0, i);
    if(parsedUrl.protocol == "https")
    {
        parsedUrl.port = 443;
    }
    std::string rest = url.substr(i + 3);
    // find auth
    std::size_t l = rest.find('@');
    if(l != std::string::npos)
    {
        parsedUrl.auth = rest.substr(0, l);
        parsedUrl.auth = Wt::Utils::urlDecode(parsedUrl.auth);
        rest = rest.substr(l+1);
    }
    // find host
    std::size_t j = rest.find('/');
    parsedUrl.host = (j == std::string::npos) ? rest : rest.substr(0,j);
    parsedUrl.path = (j == std::string::npos) ? "/" : rest.substr(j);
    std::size_t k = parsedUrl.host.find(':');
    if(k != std::string::npos)
    {
        try
        {
            parsedUrl.port = boost::lexical_cast<int>(parsedUrl.host.substr(k + 1));
        }
        catch(boost::bad_lexical_cast& e)
        {
            LOG_ERROR("invalid port: " << parsedUrl.host.substr(k + 1));
            return false;
        }
        parsedUrl.host = parsedUrl.host.substr(0, k);
    }
    return true;
}

}
}
