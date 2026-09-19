class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.9.2"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.9.2/surplies-v0.9.2-darwin-arm64.tar.gz"
    sha256 "074d92a6c2da704c32f37e4d9519d824f6accee2a722308b554db36b7e193666"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.9.2/surplies-v0.9.2-darwin-amd64.tar.gz"
    sha256 "9e1fdcfe39fe3993a3b9faf6c6dbea70ee097bff8ad2adc0c2078f8df3afa4a4"
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
