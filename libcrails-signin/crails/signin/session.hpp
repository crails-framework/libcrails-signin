#ifndef  SIGNIN_SESSION_HPP
# define SIGNIN_SESSION_HPP

# include <crails/datatree.hpp>
# include <chrono>
# include <crails/odb/connection.hpp>

namespace Crails
{
  template<typename USER>
  class Session
  {
  public:
    typedef std::shared_ptr<USER> UserPtr;

    Session(Odb::Connection& database, Data session_data) : database(database), session_data(session_data)
    {}

    std::time_t get_min_sign_in_time()
    {
      using namespace std::chrono;
      auto now = system_clock::to_time_t(system_clock::now());

      return now - USER::session_duration;
    }

    void set_current_user(UserPtr user)
    {
      set_current_user(*user);
      current_user = user;
    }

    void set_current_user(USER& user)
    {
      using namespace std::chrono;
      time_t min_sign_in_at = get_min_sign_in_time();

      if (user.get_sign_in_at() == 0 || (user.get_sign_in_at() < min_sign_in_at))
      {
        user.set_sign_in_at(system_clock::to_time_t(system_clock::now()));
        user.generate_authentication_token();
        database.save(user);
        database.commit();
      }
      session_data["auth_token"] = user.get_authentication_token();
      session_data["cuid"]       = user.get_id();
    }

    void destroy()
    {
      if (get_current_user())
      {
        current_user->set_sign_in_at(0);
        database.save(*current_user);
        database.commit();
      }
      session_data["auth_token"].destroy();
      session_data["cuid"].destroy();
    }

    UserPtr get_current_user()
    {
      if (current_user == nullptr && session_data["auth_token"].exists() && session_data["cuid"].exists())
      {
        auto auth_token = session_data["auth_token"].as<std::string>();
        auto cuid       = session_data["cuid"].as<Odb::id_type>();

        database.find_one(
          current_user,
             odb::query<USER>::id                   == cuid
          && odb::query<USER>::authentication_token == auth_token
          && odb::query<USER>::sign_in_at           >= get_min_sign_in_time()
        );
      }
      return current_user;
    }

    UserPtr const_get_current_user() const { return current_user; }

    std::string to_json()
    {
      DataTree data;

      data["cuid"]       = current_user->get_id();
      data["auth_token"] = current_user->get_authentication_token();
      data["expires_in"] = current_user->get_token_expires_in();
      return data.to_json();
    }

  private:
    Odb::Connection& database;
    Data             session_data;
    UserPtr          current_user;
  };
}

#endif
