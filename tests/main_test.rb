require 'rubygems'
require 'rack'
require 'rack/test'
require 'test/unit'
require 'mocha'
require 'digest/sha1'

require 'tests/grack_test_helper'
require 'lib/git_http'

class GitHttpTest < Test::Unit::TestCase
  include GrackTestHelper
  include Rack::Test::Methods

  def app
    config = {
      :project_root => example,
      :upload_pack => true,
      :receive_pack => true,
    }
    GitHttp::App.new(config)
  end

  def test_upload_pack_advertisement
    get "/example/info/refs?service=git-upload-pack"
    assert_equal 200, r.status
    assert_equal "application/x-git-upload-pack-advertisement", r.headers["Content-Type"]
    assert_equal "001e# service=git-upload-pack", r.body.split("\n").first
    assert_match 'multi_ack_detailed', r.body
  end

  def test_no_access_wrong_content_type_up
    post "/example/git-upload-pack"
    assert_equal 403, r.status
  end

  def test_no_access_wrong_content_type_rp
    post "/example/git-receive-pack"
    assert_equal 403, r.status
  end

  def test_no_access_wrong_method_rcp
    get "/example/git-upload-pack"
    assert_equal 400, r.status
  end

  def test_no_access_wrong_command_rcp
    post "/example/git-upload-packfile"
    assert_equal 404, r.status
  end

  def test_no_access_wrong_path_rcp
    post "/example-wrong/git-upload-pack"
    assert_equal 404, r.status
  end

  def test_upload_pack_rpc
    IO.stubs(:popen).returns(MockProcess.new)
    post "/example/git-upload-pack", {}, {"CONTENT_TYPE" => "application/x-git-upload-pack-request"}
    assert_equal 200, r.status
    assert_equal "application/x-git-upload-pack-result", r.headers["Content-Type"]
  end

  def test_receive_pack_advertisement
    get "/example/info/refs?service=git-receive-pack"
    assert_equal 200, r.status
    assert_equal "application/x-git-receive-pack-advertisement", r.headers["Content-Type"]
    assert_equal "001f# service=git-receive-pack", r.body.split("\n").first
    assert_match 'report-status', r.body
    assert_match 'delete-refs', r.body
    assert_match 'ofs-delta', r.body
  end

  def test_recieve_pack_rpc
    IO.stubs(:popen).yields(MockProcess.new)
    post "/example/git-receive-pack", {}, {"CONTENT_TYPE" => "application/x-git-receive-pack-request"}
    assert_equal 200, r.status
    assert_equal "application/x-git-receive-pack-result", r.headers["Content-Type"]
  end

  def test_info_refs_dumb
    get "/example/.git/info/refs"
    assert_equal 200, r.status
  end

  def test_info_packs
    get "/example/.git/objects/info/packs"
    assert_equal 200, r.status
    assert_match /P pack-(.*?).pack/, r.body
  end

  def test_loose_objects
    path, content = write_test_objects
    get "/example/.git/objects/#{path}"
    assert_equal 200, r.status
    assert_equal content, r.body
    remove_test_objects
  end

  def test_pack_file
    path, content = write_test_objects
    get "/example/.git/objects/pack/pack-#{content}.pack"
    assert_equal 200, r.status
    assert_equal content, r.body
    remove_test_objects
  end

  def test_index_file
    path, content = write_test_objects
    get "/example/.git/objects/pack/pack-#{content}.idx"
    assert_equal 200, r.status
    assert_equal content, r.body
    remove_test_objects
  end

  def test_text_file
    get "/example/.git/HEAD"
    assert_equal 200, r.status
    assert_equal 41, r.body.size  # submodules have detached head
  end

  def test_no_size_avail
    File.stubs('size?').returns(false)
    get "/example/.git/HEAD"
    assert_equal 200, r.status
    assert_equal 41, r.body.size  # submodules have detached head
  end

  def test_config_upload_pack_off
    a1 = app
    a1.set_config_setting(:upload_pack, false)
    session = Rack::Test::Session.new(a1)
    session.get "/example/info/refs?service=git-upload-pack"
    assert_equal 404, session.last_response.status
  end

  def test_config_receive_pack_off
    a1 = app
    a1.set_config_setting(:receive_pack, false)
    session = Rack::Test::Session.new(a1)
    session.get "/example/info/refs?service=git-receive-pack"
    assert_equal 404, session.last_response.status
  end

  def test_config_bad_service
    get "/example/info/refs?service=git-receive-packfile"
    assert_equal 404, r.status
  end

  def test_git_config_receive_pack
    app1 = GitHttp::App.new({:project_root => example})
    session = Rack::Test::Session.new(app1)

    app1.stubs(:get_git_config).with('http.receivepack').returns('')
    session.get "/example/info/refs?service=git-receive-pack"
    assert_equal 404, session.last_response.status

    app1.stubs(:get_git_config).with('http.receivepack').returns('true')
    session.get "/example/info/refs?service=git-receive-pack"
    assert_equal 200, session.last_response.status

    app1.stubs(:get_git_config).with('http.receivepack').returns('false')
    session.get "/example/info/refs?service=git-receive-pack"
    assert_equal 404, session.last_response.status
  end

  def test_git_config_upload_pack
    app1 = GitHttp::App.new({:project_root => example})
    session = Rack::Test::Session.new(app1)

    app1.stubs(:get_git_config).with('http.uploadpack').returns('')
    session.get "/example/info/refs?service=git-upload-pack"
    assert_equal 200, session.last_response.status

    app1.stubs(:get_git_config).with('http.uploadpack').returns('true')
    session.get "/example/info/refs?service=git-upload-pack"
    assert_equal 200, session.last_response.status

    app1.stubs(:get_git_config).with('http.uploadpack').returns('false')
    session.get "/example/info/refs?service=git-upload-pack"
    assert_equal 404, session.last_response.status
  end

  def test_recognize_git_dir
    assert !GitHttp::App.git_dir?(File.join(example,'example'))
    assert GitHttp::App.git_dir?(File.join(example,'example','.git'))
  end

  def test_return_404_on_non_existing_git_dir
    app1 = GitHttp::App.new({:project_root => example})
    session = Rack::Test::Session.new(app1)

    session.get "/example2/info/refs?service=git-upload-pack"
    assert_equal 404, session.last_response.status
  end

  def test_create_directory_if_creation_is_allowed
    IO.stubs(:popen).returns(MockProcess.new)
    app1 = GitHttp::App.new({:project_root => example})
    app1.stubs(:get_git_config).with('http.uploadpack').returns('true')
    app1.stubs(:get_git_config).with('http.receivepack').returns('true')
    app1.allow_creation!
    session = Rack::Test::Session.new(app1)
    require 'fileutils'
    tmp_path = File.join(example,'example-notyetexistant')
    GitHttp::App.expects(:no_git_subdir?).with(tmp_path).returns(true)

    session.post "/example-notyetexistant/git-receive-pack", {}, {"CONTENT_TYPE" => "application/x-git-receive-pack-request" }
    FileUtils.remove_entry_secure(tmp_path,true)
    assert_equal 200, session.last_response.status

    # in a subsequent request allow_creation is unset
    session.post "/example-notyetexistant/git-receive-pack", {}, {"CONTENT_TYPE" => "application/x-git-receive-pack-request" }
    assert_equal 404, session.last_response.status
  end

  def test_figure_out_git_subdir
    require 'fileutils'
    tmp_path = File.join('/tmp',"#{sprintf('%s%d.%d', 'nogit', $$, 42)}")
    FileUtils.mkdir_p(tmp_path)
    assert GitHttp::App.no_git_subdir?(tmp_path)
    Dir.rmdir(tmp_path)
    assert !GitHttp::App.no_git_subdir?(File.join(example,'lib'))
  end

  private

  def r
    last_response
  end

  def write_test_objects
    content = Digest::SHA1.hexdigest('gitrocks')
    base = File.join(File.expand_path(File.dirname(__FILE__)), 'example', '.git', 'objects')    
    obj = File.join(base, '20')
    Dir.mkdir(obj) rescue nil
    file = File.join(obj, content[0, 38])
    File.open(file, 'w') { |f| f.write(content) }
    pack = File.join(base, 'pack', "pack-#{content}.pack")
    File.open(pack, 'w') { |f| f.write(content) }
    idx = File.join(base, 'pack', "pack-#{content}.idx")
    File.open(idx, 'w') { |f| f.write(content) }
    ["20/#{content[0,38]}", content]
  end

  def remove_test_objects
    content = Digest::SHA1.hexdigest('gitrocks')
    base = File.join(File.expand_path(File.dirname(__FILE__)), 'example', '.git', 'objects')    
    obj = File.join(base, '20')
    file = File.join(obj, content[0, 38])
    pack = File.join(base, 'pack', "pack-#{content}.pack")
    idx = File.join(base, 'pack', "pack-#{content}.idx")
    File.unlink(file)
    File.unlink(pack)
    File.unlink(idx)
  end

end