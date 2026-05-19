class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.5.3"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.5.3/surplies-v0.5.3-darwin-arm64.tar.gz"
    sha256 "22fe46b81e04c3cdd533847aa05f3bbc6a34b5a01d83642083ded0efacfb630e"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.5.3/surplies-v0.5.3-darwin-amd64.tar.gz"
    sha256 "22263875b5ca8ddde8fa21777cf470b20a01621731487a215f2dd406fd48e7f9"
  else
    odie "surplies is only supported on macOS via Homebrew. Build from source for Linux."
  end

  def install
    bin.install "surplies-darwin-arm64" => "surplies" if Hardware::CPU.arm?
    bin.install "surplies-darwin-amd64" => "surplies" if Hardware::CPU.intel?
  end

  test do
    system bin/"surplies", "-version"
  end
end
