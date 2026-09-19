class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.9.1"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.9.1/surplies-v0.9.1-darwin-arm64.tar.gz"
    sha256 "883411062748b18b440b9ff80259b5ed3ec5bfb525c3db28291a986b504bc2df"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.9.1/surplies-v0.9.1-darwin-amd64.tar.gz"
    sha256 "0c1fec7d187f574d3ffd891f1a466d660063734361988a33704f5f3473eb52b1"
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
