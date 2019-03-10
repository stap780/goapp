class Ability
  include CanCan::Ability

  def initialize(user, cname) # cname из aplication controller для определения Модели
		alias_action :index, :show, :to => :read
		alias_action :new, :to => :create
		alias_action :edit, :to => :update
    # Define abilities for the passed in user here. For example:
      user ||= User.new # guest user (not logged in)
      if user.role == "admin"
        can :manage, :all
      else
        #can :read, :all
				user.permissions.each do |permission|
				  if permission.subject_class == "all" # это из примера в интернете (там чуть другая организация коллекции названия моделей)
				    can permission.action.to_sym, permission.subject_class.to_sym
				  else
# Это пример логики
# 				  	if user.id == 10
# 					   can :manage, Okrug
# 					   can :read, Driver
# 					   can :create, Driver
# 					  end
      puts cname
# Это первая версия
# 						if permission.subject_class.constantize == cname
# 						can :read, :all
# 						end
# 						if permission.value == true
# 				    	can permission.action.to_sym, permission.subject_class.constantize
# 				    end
# Это вторая версия
      puts permission.permcl.systitle
      puts permission.permcl_action.title
						if permission.permcl.systitle.constantize == cname
						can :read, :all
						end
				    can permission.permcl_action.title.to_sym, permission.permcl.systitle.constantize
					end
      	end
      end
    #
    #Стандартные соглашения по страницам CRUD в cancan
# 		alias_action :index, :show, :to => :read
# 		alias_action :new, :to => :create
# 		alias_action :edit, :to => :update

    # The first argument to `can` is the action you are giving the user
    # permission to do.
    # If you pass :manage it will apply to every action. Other common actions
    # here are :read, :create, :update and :destroy.
    #
    # The second argument is the resource the user can perform the action on.
    # If you pass :all it will apply to every resource. Otherwise pass a Ruby
    # class of the resource.
    #
    # The third argument is an optional hash of conditions to further filter the
    # objects.
    # For example, here the user can only update published articles.
    #
    #   can :update, Article, :published => true
    #
    # See the wiki for details:
    # https://github.com/CanCanCommunity/cancancan/wiki/Defining-Abilities
  end
end
