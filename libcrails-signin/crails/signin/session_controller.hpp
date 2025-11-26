#ifndef  CRAILS_SESSION_CONTROLLER_HPP
# define CRAILS_SESSION_CONTROLLER_HPP

# include <crails/context.hpp>
# include <crails/signin/session.hpp>

# define signin_actions(path, controller) \
  match_action("GET",    path, controller, show) \
 .match_action("POST",   path, controller, create) \
 .match_action("DELETE", path, controller, destroy)

namespace Crails
{
  template<typename USER, typename SUPER>
  class SessionController : public SUPER
  {
  public:
    typedef std::shared_ptr<USER> UserPtr;

    SessionController(Crails::Context& context) : SUPER(context), user_session(SUPER::database, SUPER::session)
    {
    }

    virtual void on_session_created() { show(); }
    virtual void on_session_destroyed() { }
    virtual void on_session_not_created() { SUPER::respond_with(HttpStatus::bad_request); }

    void show()
    {
      auto user = user_session.get_current_user();

      if (user)
      {
        DataTree response_body;

        response_body["auth_token"] = user->get_authentication_token();
        response_body["cuid"]       = user->get_id();
        response_body["expires_in"] = user->get_token_expires_in();
        SUPER::render(SUPER::JSON, response_body.as_data());
      }
      else
        SUPER::respond_with(HttpStatus::forbidden);
    }

    void create()
    {
      UserPtr user = find_user();

      if (user != nullptr)
      {
        user_session.set_current_user(user);
        on_session_created();
      }
      else
        on_session_not_created();
    }

    void destroy()
    {
      if (user_session.get_current_user())
      {
        user_session.destroy();
        on_session_destroyed();
      }
      else
        SUPER::respond_with(HttpStatus::forbidden);
    }

  protected:
    virtual UserPtr find_user() = 0;

    Session<USER> user_session;
  };
}

#endif
