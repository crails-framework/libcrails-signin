#ifndef  SIGNIN_AUTH_CONTROLLER_HPP
# define SIGNIN_AUTH_CONTROLLER_HPP

# include <crails/controller.hpp>
# include <crails/signin/session.hpp>

namespace Crails
{
  template<typename USER, typename SUPER>
  class AuthController : public SUPER
  {
  public:
    AuthController(Crails::Context& context) : SUPER(context), user_session(SUPER::database, SUPER::session)
    {
    }

    void initialize()
    {
      SUPER::initialize();
      initialize_required_user();
    }

    virtual bool require_authentified_user() const { return false; }

    virtual void on_user_not_authenticated() { SUPER::respond_with(HttpStatus::unauthorized); }

    void initialize_required_user()
    {
      if (require_authentified_user())
        initialize_current_user();
    }

  protected:
    bool initialize_current_user()
    {
      if (user_session.get_current_user() == nullptr)
        on_user_not_authenticated();
      return true;
    }

    Session<USER> user_session;
  };
}

#endif
