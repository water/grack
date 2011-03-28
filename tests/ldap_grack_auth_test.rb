require 'rubygems'
require 'rack'
require 'rack/test'
require 'test/unit'
require 'mocha'
require 'tests/grack_test_helper'
require 'lib/git_http'
require 'lib/ldap_grack_auth'

class LdapGrackAuthTest < Test::Unit::TestCase
  include GrackTestHelper
  include Rack::Test::Methods
  
  def setup
    mock_ldap
  end
  
  def test_should_fail_if_no_auth
    get "/example/.git/info/refs"
    assert_equal 401, last_response.status
  end  
  
  def test_should_fail_if_no_auth_provided
    Rack::Auth::Basic::Request.any_instance.expects(:provided?).returns(false)
    Rack::Auth::Basic::Request.any_instance.expects(:basic?).never
    LdapGrackAuth.any_instance.expects(:valid?).never
    
    get "/example/.git/info/refs"
    assert_equal 401, last_response.status
  end

  def test_should_fail_if_no_basic_auth
    Rack::Auth::Basic::Request.any_instance.expects(:provided?).returns(true)
    Rack::Auth::Basic::Request.any_instance.expects(:basic?).returns(false)
    LdapGrackAuth.any_instance.expects(:valid?).never
    
    get "/example/.git/info/refs"
    assert_equal 400, last_response.status
  end
  
  def test_should_use_ldap_authentication
    LdapGrackAuth.any_instance.expects(:valid?).returns(true)

    authorize 'nice', 'girl'
    get "/example/.git/info/refs"
    assert_equal 200, last_response.status
  end
  
  def test_should_fail_if_authorization_fails
    LdapGrackAuth.any_instance.expects(:valid?).returns(false)

    authorize 'bad', 'boy'
    get "/example/.git/info/refs"
    assert_equal 401, last_response.status
  end
  
  def test_should_fail_if_binding_fails
    MockLdap.any_instance.expects(:bind_as).with(:base => app.config[:ldap_base], :filter => 'uid=bad', :password => 'boy').returns(false)

    authorize 'bad', 'boy'
    get "/example/.git/info/refs"
    assert_equal 401, last_response.status    
  end

  def test_should_not_require_group_by_default
    MockLdap.any_instance.expects(:bind_as).with(
      :base => app.config[:ldap_base],
      :filter => 'uid=nice',
      :password => 'girl'
    ).returns([nice_girl_ldap])

    authorize 'nice', 'girl'
    get "/example/.git/info/refs"
    assert_equal 200, last_response.status    
  end
  
  def test_should_succeed_if_group_is_required_and_user_is_in_group
    MockLdap.any_instance.expects(:bind_as).with(
      :base => app.config[:ldap_base],
      :filter => 'uid=nice',
      :password => 'girl'
    ).returns([nice_girl_ldap])

    MockLdap.any_instance.expects(:search).with(
      :base => app.config[:ldap_base],
      :attributes => ['cn','gidNumber','memberUid'],
      :filter => '(objectClass=posixGroup)'
    ).returns([{:cn => ['git_access'], :gidnumber=> ['1'], :memberuid => ['ngirl']}])
    app.config[:ldap_require_groups] = 'git_access'
    
    authorize 'nice', 'girl'
    get "/example/.git/info/refs"
    
    assert_equal 200, last_response.status
  end

  def test_should_succeed_if_group_is_required_and_user_has_group_as_primary_group
    MockLdap.any_instance.expects(:bind_as).with(
      :base => app.config[:ldap_base],
      :filter => 'uid=nice',
      :password => 'girl'
    ).returns([nice_girl_ldap])

    MockLdap.any_instance.expects(:search).with(
      :base => app.config[:ldap_base],
      :attributes => ['cn','gidNumber','memberUid'],
      :filter => '(objectClass=posixGroup)'
    ).returns([{:cn => ['base_group'], :gidnumber=> ['2'], :memberuid => []},{:cn => ['git_access'], :gidnumber=> ['1'], :memberuid => ['ngirl']}])
    app.config[:ldap_require_groups] = 'base_group'
    
    authorize 'nice', 'girl'
    get "/example/.git/info/refs"
    
    assert_equal 200, last_response.status
  end
  def test_should_succeed_if_group_is_required_and_user_has_group_as_primary_group_array
    MockLdap.any_instance.expects(:bind_as).with(
      :base => app.config[:ldap_base],
      :filter => 'uid=nice',
      :password => 'girl'
    ).returns([nice_girl_ldap])

    MockLdap.any_instance.expects(:search).with(
      :base => app.config[:ldap_base],
      :attributes => ['cn','gidNumber','memberUid'],
      :filter => '(objectClass=posixGroup)'
    ).returns([{:cn => ['base_group'], :gidnumber=> ['2'], :memberuid => []},{:cn => ['git_access'], :gidnumber=> ['1'], :memberuid => ['ngirl']}])
    app.config[:ldap_require_groups] = ['foo_group','base_group']
    
    authorize 'nice', 'girl'
    get "/example/.git/info/refs"
    
    assert_equal 200, last_response.status
  end  
  def test_should_fail_on_users_url_with_rw_access_but_not_myself
    MockLdap.any_instance.expects(:bind_as).with(
      :base => app.config[:ldap_base],
      :filter => 'uid=nice',
      :password => 'girl'
    ).returns([nice_girl_ldap])

    MockLdap.any_instance.expects(:search).with(
      :base => app.config[:ldap_base],
      :attributes => ['cn','gidNumber','memberUid'],
      :filter => '(objectClass=posixGroup)'
    ).returns([{:cn => ['base_group'], :gidnumber=> ['2'], :memberuid => []},{:cn => ['git_access'], :gidnumber=> ['1'], :memberuid => ['ngirl']}])
    app.config[:ldap_require_groups] = 'base_group'

    authorize 'nice', 'girl'
    IO.stubs(:popen).yields(MockProcess.new)
    post "/users/bboy/foobar/git-receive-pack", {}, {"CONTENT_TYPE" => "application/x-git-receive-pack-request"}
    
    assert_equal 401, last_response.status    
  end

  def test_should_fail_on_users_url_with_rw_access_but_not_myself_array
    MockLdap.any_instance.expects(:bind_as).with(
      :base => app.config[:ldap_base],
      :filter => 'uid=nice',
      :password => 'girl'
    ).returns([nice_girl_ldap])

    MockLdap.any_instance.expects(:search).with(
      :base => app.config[:ldap_base],
      :attributes => ['cn','gidNumber','memberUid'],
      :filter => '(objectClass=posixGroup)'
    ).returns([{:cn => ['base_group'], :gidnumber=> ['2'], :memberuid => []},{:cn => ['git_access'], :gidnumber=> ['1'], :memberuid => ['ngirl']}])
    app.config[:ldap_require_groups] = ['base_group','foo_group']

    authorize 'nice', 'girl'
    IO.stubs(:popen).yields(MockProcess.new)
    post "/users/bboy/foobar/git-receive-pack", {}, {"CONTENT_TYPE" => "application/x-git-receive-pack-request"}
    
    assert_equal 401, last_response.status    
  end

  def test_should_succeed_on_my_users_url_with_rw_access
    MockLdap.any_instance.expects(:bind_as).with(
      :base => app.config[:ldap_base],
      :filter => 'uid=nice',
      :password => 'girl'
    ).returns([nice_girl_ldap])

    MockLdap.any_instance.expects(:search).with(
      :base => app.config[:ldap_base],
      :attributes => ['cn','gidNumber','memberUid'],
      :filter => '(objectClass=posixGroup)'
    ).returns([{:cn => ['base_group'], :gidnumber=> ['2'], :memberuid => []},{:cn => ['git_access'], :gidnumber=> ['1'], :memberuid => ['ngirl']}])
    app.config[:ldap_require_groups] = 'base_group'
    # map any request back to our example git repo
    GitHttp::App.any_instance.expects(:get_git_dir).with('/users/ngirl/foobar').returns(example)
    
    authorize 'nice', 'girl'
    IO.stubs(:popen).yields(MockProcess.new)
    post "/users/ngirl/foobar/git-receive-pack", {}, {"CONTENT_TYPE" => "application/x-git-receive-pack-request"}
    
    assert_equal 200, last_response.status
  end
  
  def test_should_fail_on_root_user_url
    MockLdap.any_instance.expects(:bind_as).with(
      :base => app.config[:ldap_base],
      :filter => 'uid=nice',
      :password => 'girl'
    ).returns([nice_girl_ldap])

    MockLdap.any_instance.expects(:search).with(
      :base => app.config[:ldap_base],
      :attributes => ['cn','gidNumber','memberUid'],
      :filter => '(objectClass=posixGroup)'
    ).returns([{:cn => ['base_group'], :gidnumber=> ['2'], :memberuid => []},{:cn => ['git_access'], :gidnumber=> ['1'], :memberuid => ['ngirl']}])
    app.config[:ldap_require_groups] = 'base_group'
    
    authorize 'nice', 'girl'
    IO.stubs(:popen).yields(MockProcess.new)
    post "/users/ngirl/git-receive-pack", {}, {"CONTENT_TYPE" => "application/x-git-receive-pack-request"}
    
    assert_equal 401, last_response.status
  end

  def test_should_succeed_with_rw_on_a_project_url_where_project_member
    MockLdap.any_instance.expects(:bind_as).with(
      :base => app.config[:ldap_base],
      :filter => 'uid=nice',
      :password => 'girl'
    ).returns([nice_girl_ldap])

    MockLdap.any_instance.expects(:search).with(
      :base => app.config[:ldap_base],
      :attributes => ['cn','gidNumber','memberUid'],
      :filter => '(objectClass=posixGroup)'
    ).returns([{:cn => ['base_group'], :gidnumber=> ['2'], :memberuid => []},{:cn => ['project_foo'], :gidnumber=> ['1'], :memberuid => ['ngirl']}])
    app.config[:ldap_require_groups] = 'base_group'

    # map any request back to our example git repo
    GitHttp::App.any_instance.expects(:get_git_dir).with('/project_foo/foobar').returns(example)
    
    authorize 'nice', 'girl'
    IO.stubs(:popen).yields(MockProcess.new)
    post "/project_foo/foobar/git-receive-pack", {}, {"CONTENT_TYPE" => "application/x-git-receive-pack-request"}
    
    assert_equal 200, last_response.status    
  end

  def test_should_fail_on_root_project_url
    MockLdap.any_instance.expects(:bind_as).with(
      :base => app.config[:ldap_base],
      :filter => 'uid=nice',
      :password => 'girl'
    ).returns([nice_girl_ldap])

    MockLdap.any_instance.expects(:search).with(
      :base => app.config[:ldap_base],
      :attributes => ['cn','gidNumber','memberUid'],
      :filter => '(objectClass=posixGroup)'
    ).returns([{:cn => ['base_group'], :gidnumber=> ['2'], :memberuid => []},{:cn => ['project_foo'], :gidnumber=> ['1'], :memberuid => ['ngirl']}])
    app.config[:ldap_require_groups] = 'base_group'

    authorize 'nice', 'girl'
    IO.stubs(:popen).yields(MockProcess.new)
    post "/project_foo/git-receive-pack", {}, {"CONTENT_TYPE" => "application/x-git-receive-pack-request"}
    
    assert_equal 401, last_response.status    
  end

  def test_should_fail_with_rw_on_a_project_url_where_not_project_member
    MockLdap.any_instance.expects(:bind_as).with(
      :base => app.config[:ldap_base],
      :filter => 'uid=nice',
      :password => 'girl'
    ).returns([nice_girl_ldap])

    MockLdap.any_instance.expects(:search).with(
      :base => app.config[:ldap_base],
      :attributes => ['cn','gidNumber','memberUid'],
      :filter => '(objectClass=posixGroup)'
    ).returns([{:cn => ['base_group'], :gidnumber=> ['2'], :memberuid => []},{:cn => ['project_foo'], :gidnumber=> ['1'], :memberuid => ['bboy']}])
    app.config[:ldap_require_groups] = 'base_group'
    
    authorize 'nice', 'girl'
    IO.stubs(:popen).yields(MockProcess.new)
    post "/project_foo/foobar/git-receive-pack", {}, {"CONTENT_TYPE" => "application/x-git-receive-pack-request"}
    
    assert_equal 401, last_response.status    
  end

  def test_should_succeed_with_rw_on_a_project_url_where_project_member_with_project_prefix
    MockLdap.any_instance.expects(:bind_as).with(
      :base => app.config[:ldap_base],
      :filter => 'uid=nice',
      :password => 'girl'
    ).returns([nice_girl_ldap])

    MockLdap.any_instance.expects(:search).with(
      :base => app.config[:ldap_base],
      :attributes => ['cn','gidNumber','memberUid'],
      :filter => '(objectClass=posixGroup)'
    ).returns([{:cn => ['base_group'], :gidnumber=> ['2'], :memberuid => []},{:cn => ['project_foo'], :gidnumber=> ['1'], :memberuid => ['ngirl']}])
    app.config[:ldap_require_groups] = 'base_group'
    app.config[:ldap_group_prefix] = 'project_'

    # map any request back to our example git repo
    GitHttp::App.any_instance.expects(:get_git_dir).with('/foo/foobar').returns(example)
    
    authorize 'nice', 'girl'
    IO.stubs(:popen).yields(MockProcess.new)
    post "/foo/foobar/git-receive-pack", {}, {"CONTENT_TYPE" => "application/x-git-receive-pack-request"}
    
    assert_equal 200, last_response.status    
  end


  def test_should_fail_with_rw_on_a_project_url_where_not_project_member_with_project_prefix
    MockLdap.any_instance.expects(:bind_as).with(
      :base => app.config[:ldap_base],
      :filter => 'uid=nice',
      :password => 'girl'
    ).returns([nice_girl_ldap])

    MockLdap.any_instance.expects(:search).with(
      :base => app.config[:ldap_base],
      :attributes => ['cn','gidNumber','memberUid'],
      :filter => '(objectClass=posixGroup)'
    ).returns([{:cn => ['base_group'], :gidnumber=> ['2'], :memberuid => []},{:cn => ['project_foo'], :gidnumber=> ['1'], :memberuid => ['bboy']}])
    app.config[:ldap_require_groups] = 'base_group'
    app.config[:ldap_group_prefix] = 'project_'
    
    authorize 'nice', 'girl'
    IO.stubs(:popen).yields(MockProcess.new)
    post "/foo/foobar/git-receive-pack", {}, {"CONTENT_TYPE" => "application/x-git-receive-pack-request"}
    
    assert_equal 401, last_response.status    
  end

  private
  def app
    @app ||= Rack::Builder.parse_file(File.join(example,'ldap_auth','config.ru')).first
  end
  
  def mock_ldap
    Net::LDAP.stubs(:new).returns(MockLdap.new)
  end
  
  def nice_girl_ldap
    { :uid => ['ngirl'],:uidnumber => ['42'], :gidnumber => ['2'] }
  end
end

class MockLdap
  
end