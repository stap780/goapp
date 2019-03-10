class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  rescue_from CanCan::AccessDenied do |exception|
    puts exception
    flash[:error] = "Access denied."
    redirect_to root_url
	end

  protect_from_forgery with: :exception

  def authorize
    redirect_to login_url, alert: "Not authorized" if current_user.nil?
  end

  private
  def current_user
    @current_user ||= User.find_by_auth_token( cookies[:auth_token]) if cookies[:auth_token]
  end
  helper_method :current_user

  def current_ability
		cname = controller_name.classify.constantize
		@current_ability ||= Ability.new(current_user, cname)
	end

end
