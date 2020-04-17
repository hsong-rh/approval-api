class Group
  attr_accessor :name
  attr_accessor :description
  attr_accessor :uuid
  attr_writer   :users
  attr_writer   :roles

  def self.find(uuid)
    group = nil
    Insights::API::Common::RBAC::Service.call(RBACApiClient::GroupApi, Thread.current[:rbac_extra_headers] || {}) do |api|
      group = from_raw(api.get_group(uuid))
    end
    group
  end

  def self.all(username = nil)
    groups = []
    Insights::API::Common::RBAC::Service.call(RBACApiClient::GroupApi, Thread.current[:rbac_extra_headers] || {}) do |api|
      Insights::API::Common::RBAC::Service.paginate(api, :list_groups, :username => username).each do |item|
        groups << from_raw(item)
      end
    end
    groups
  end

  def users
    @users ||= Group.find(uuid).users
  end

  def roles
    @roles ||= Group.find(uuid).roles
  end

  def approver_role?
    context ||= Insights::API::Common::Request.current.to_h.transform_keys(&:to_s)
    ContextService.new(context).as_org_admin do
      scopes.include?("admin") || scopes.include?("group")
    end
  end

  private

  def scopes
    regexp = Regexp.new("(approval):(actions):(create)")

    acls.each_with_object([]) do |acl, memo|
      if regexp.match?(acl.permission)
        memo << acl_scopes(acl)
      end
    end.flatten.uniq.sort
  end

  def acl_scopes(acl)
    acl.resource_definitions.each_with_object([]) do |rd, memo|
      if rd.attribute_filter.key == 'scope' && rd.attribute_filter.operation == 'equal'
        memo << rd.attribute_filter.value
      end
    end
  end

  def acls
    Insights::API::Common::RBAC::Service.call(RBACApiClient::RoleApi, Thread.current[:rbac_extra_headers] || {}) do |api|
      roles.each_with_object([]) do |role, acls|
        Insights::API::Common::RBAC::Service.paginate(api, :get_role_access, {}, role.uuid).each do |acl|
          acls << acl
        end
      end
    end
  end

  private_class_method def self.from_raw(raw_group)
    new.tap do |group|
      group.uuid = raw_group.uuid
      group.name = raw_group.name
      group.description = raw_group.description
      group.users = raw_group.try(:principals)
      group.roles = raw_group.try(:roles)
    end
  end
end
