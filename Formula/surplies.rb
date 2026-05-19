class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.5.2"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.5.2/surplies-v0.5.2-darwin-arm64.tar.gz"
    sha256 "b2c7735f090177f13addeaae2e39b29290fc9ed110f83bc7b147534df734d3f6"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.5.2/surplies-v0.5.2-darwin-amd64.tar.gz"
    sha256 "ced6da4a26f4ad24e28c93926b4d9872bc149b5f225c247073c17e5d48e05667"
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
