/*
 * Copyright (C) 2012 Emweb bvba, Kessel-Lo, Belgium.
 *
 * See the LICENSE file for terms of use.
 */

#include <Wt/Dbo/Dbo>
#include <Wt/Dbo/backend/Sqlite3>

#include "Person.h"
#include "Membership.h"
#include "Organisation.h"
#include "MembershipId.h"

namespace dbo = Wt::Dbo;

class Membership;
class Organisation;
class Person;

void run()
{
  /*
   * Setup a session, would typically be done once at application startup.
   */
  dbo::backend::Sqlite3 sqlite3(":memory:");
  sqlite3.setProperty("show-queries", "true");
  dbo::Session session;
  session.setConnection(sqlite3);
  
  session.mapClass<Membership > ("membership");
  session.mapClass<Person > ("person");
  session.mapClass<Organisation > ("organisation");
  
  /*
   * Try to create the schema (will fail if already exists).
   */
  session.createTables();
  
  {
    dbo::Transaction transaction(session);
    
    Person *p = new Person();
    p->name = "Joe";
    dbo::ptr<Person> joe = session.add(p);
    
    Organisation *o = new Organisation();
    o->name = "Police";
    dbo::ptr<Organisation> police = session.add(o);
    
    Membership *ms = new Membership();
    ms->id.person = joe;
    ms->id.organisation = police;
    ms->karma = 42;
    
    session.add(ms);
  }
}

int main(int argc, char **argv)
{
  run();
}