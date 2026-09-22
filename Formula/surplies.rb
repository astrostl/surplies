class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.15.0"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.15.0/surplies-v0.15.0-darwin-arm64.tar.gz"
    sha256 "435c94f5b408e80ac345f0f3ed27636e3cb0ee6324343ce0034aab62a5a9bffd"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.15.0/surplies-v0.15.0-darwin-amd64.tar.gz"
    sha256 "c9c4914f52c7a6b8cb788a860dcf62dd4fe9280dbccfe4674e94a7bccde9fe66"
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
