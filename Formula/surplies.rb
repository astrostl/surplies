class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.7.0"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.7.0/surplies-v0.7.0-darwin-arm64.tar.gz"
    sha256 "44c02add386f611ba934dd06cc69091adaaf7ed2cc2d2324eca7e65e3d8dac63"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.7.0/surplies-v0.7.0-darwin-amd64.tar.gz"
    sha256 "d7e44e0254263c12ce67d0f01f28d917593c7fc92af0dc1fc8665be8f66f1a0c"
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
