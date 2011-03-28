module GrackTestHelper
  def example
    File.expand_path(File.dirname(__FILE__))
  end
end

class MockProcess

  def initialize
    @counter = 0
  end

  def write(data)
  end

  def read(data)
  end

  def eof?
    @counter += 1
    @counter > 1 ? true : false
  end

end
