// This may look like C code, but it's really -*- C++ -*-
/*
 * Copyright (C) 2016 Emweb bvba, Herent, Belgium.
 *
 * See the LICENSE file for terms of use.
 */
#ifndef WFILEDROPCONTAINER_WIDGET_H_
#define WFILEDROPCONTAINER_WIDGET_H_

#include "Wt/WContainerWidget.h"
#include "Wt/WResource.h"

namespace Wt
{

    class WFileDropUploadResource;

    /*! \class WFileDropWidget Wt/WFileDropWidget.h Wt/WFileDropWidget.h
     *  \brief A widget that allows dropping files for upload.
     *
     * This widget accepts files that are dropped into it. A signal is triggered
     * whenever one or more files are dropped. The filename, type and size of
     * these files is immediately available through the WFileDropWidget::File
     * interface.
     *
     * The file upload is done sequentially. All files before the currentIndex()
     * have either finished, failed or have been cancelled.
     *
     * The widget has the default style-class 'Wt-filedropzone'. An additional
     * style class is applied when files are hovered over the widget. This can be
     * configured using the method setHoverStyleClass().
     */
    class WT_API WFileDropWidget : public WContainerWidget
    {
        public:
            /*! \class File
             *  \brief A nested class of WFileDropWidget representing a file
             *
             * The methods returning the filename, mime-type and size return valid
             * values if the upload of this file is not yet finished. The method
             * uploadedFile() is only available after the upload is finished.
             */
            class WT_API File : public WObject
            {
                public:
                    /*! \brief Returns the client filename.
                     */
                    const std::string & clientFileName() const
                    {
                        return clientFileName_;
                    }

                    /*! \brief Returns the mime-type of the file.
                     */
                    const std::string & mimeType() const
                    {
                        return type_;
                    }

                    /*! \brief Returns the size of the file.
                     */
                    ::uint64_t size() const
                    {
                        return size_;
                    }

                    /*! \brief Returns the uploaded file as a Http::UploadedFile.
                     *
                     * This method will throw an expection if the upload is not yet finished.
                     *
                     * \sa uploadFinished()
                     */
                    const Http::UploadedFile & uploadedFile() const;

                    /*! \brief Returns true if the upload is finished.
                     *
                     * When this method returns true, the uploaded file is available on the
                     * server.
                     *
                     * \sa uploadedFile()
                     */
                    bool uploadFinished() const
                    {
                        return uploadFinished_;
                    }

                    /*! \brief This signal allows you to track the upload progress of the file.
                     */
                    Signal< ::uint64_t, ::uint64_t > & dataReceived()
                    {
                        return dataReceived_;
                    }

                    /*! \brief This signal is triggered when the upload is finished.
                     *
                     * This is also signalled using the WFileDropWidget
                     * \link WFileDropWidget::uploaded uploaded() \endlink signal.
                     */
                    Signal<> & uploaded()
                    {
                        return uploaded_;
                    }

                    // Wt internal
                    File(int id, const std::string & fileName, const std::string & type, ::uint64_t size);
                    int uploadId() const
                    {
                        return id_;
                    }
                    void setUploadedFile(const Http::UploadedFile & file);
                    void cancel();
                    bool cancelled() const;

                private:
                    int id_;
                    std::string clientFileName_;
                    std::string type_;
                    ::uint64_t size_;
                    Http::UploadedFile uploadedFile_;
                    Signal< ::uint64_t, ::uint64_t > dataReceived_;
                    Signal<> uploaded_;

                    bool uploadFinished_;
                    bool cancelled_;
            };


            /*! \brief Constructor
             */
            WFileDropWidget();

            /*! \brief Returns the vector of uploads managed by this widget.
             *
             * The files in this vector are handled sequentially by the widget. All
             * WFileDropWidget::File objects in this vector have either finished or
             * failed if they are before the currentIndex(), depending on the return
             * value of WFileDropWidget::File::uploadFinished(). The other files are
             * still being handled.
             *
             * \sa currentIndex()
             */
            const std::vector<File *> & uploads() const
            {
                return uploads_;
            }

            /*! \brief Return the index of the file that is currently being handled.
             *
             * If nothing is to be done, this will return the size of the vector returned
             * by uploads().
             */
            int currentIndex() const
            {
                return currentFileIdx_;
            }

            /*! \brief Cancels the upload of a file.
             *
             * If you cancel a file that is still waiting to be uploaded, it will stay
             * in the uploads() vector, but it will be skipped.
             */
            void cancelUpload(File * file);

            /*! \brief Removes the file.
             *
             * This can be used to free resources of files that were already uploaded. A
             * file can only be removed if its index in uploads() is before the current
             * index.
             */
            bool remove(File * file);

            /*! \brief When set to false, the widget no longer accepts any files.
             */
            void setAcceptDrops(bool enable);

            /*! \brief Set the style class that is applied when a file is hovered over
             * the widget.
             */
            void setHoverStyleClass(const std::string & className);

            /*! \brief Sets input accept attributes
             *
             * The accept attribute may be specified to provide user agents with a
             * hint of what file types will be accepted. Use html input accept attributes
             * as input.
             * This only affects the popup that is shown when users click on the widget.
             * A user can still drop any file type.
             */
            void setFilters(const std::string & acceptAttributes);

            /*! \brief The signal triggers if one or more files are dropped.
             */
            Signal<std::vector<File *> > & drop()
            {
                return dropEvent_;
            }

            /*! \brief The signal triggers when the upload of a file is about to begin.
             *
             * After this signal is triggered, the upload automatically starts. The
             * upload can still fail if the file is too large or if there is a network
             * error.
             */
            Signal<File *> & newUpload()
            {
                return uploadStart_;
            }

            /*! \brief The signal is triggered if any file finished uploading.
             */
            Signal<File *> & uploaded()
            {
                return uploaded_;
            }

            /*! \brief The signal triggers when a file is too large for upload.
             *
             * This signal is triggered when the widget attempts to upload the file.
             */
            Signal<File *, ::uint64_t> & tooLarge()
            {
                return tooLarge_;
            }

            /*! \brief The signal triggers when an upload failed.
             *
             * This signal will trigger when the widget skips over one of the files
             * in the list for an unknown reason (e.g. happens when you drop a folder).
             */
            Signal<File *> & uploadFailed()
            {
                return uploadFailed_;
            }

        protected:
            virtual void enableAjax() override;
            virtual void updateDom(DomElement & element, bool all) override;

        private:
            void setup();
            void handleDrop(const std::string & newDrops);
            void handleTooLarge(::uint64_t size);
            void handleSendRequest(int id);
            void emitUploaded(int id);
            void stopReceiving();
            void onData(::uint64_t current, ::uint64_t total);
            void onDataExceeded(::uint64_t dataExceeded);

            // Functions for handling incoming requests
            void setUploadedFile(Http::UploadedFile file);
            bool incomingIdCheck(int id);

            class WFileDropUploadResource;
            WFileDropUploadResource * resource_;
            unsigned currentFileIdx_;

            std::string hoverStyleClass_;
            bool acceptDrops_;
            std::string acceptAttributes_;

            JSignal<std::string> dropSignal_;
            JSignal<int> requestSend_;
            JSignal< ::uint64_t > fileTooLarge_;
            JSignal<int> uploadFinished_;
            JSignal<> doneSending_;

            Signal<std::vector<File *> > dropEvent_;
            Signal<File *> uploadStart_;
            Signal<File *> uploaded_;
            Signal< File *, ::uint64_t > tooLarge_;
            Signal<File *> uploadFailed_;

            std::vector<File *> uploads_;

            static const int BIT_HOVERSTYLE_CHANGED  = 0;
            static const int BIT_ACCEPTDROPS_CHANGED = 1;
            static const int BIT_FILTERS_CHANGED     = 2;
            std::bitset<3> updateFlags_;

            friend class WFileDropUploadResource;
    };

}

#endif
