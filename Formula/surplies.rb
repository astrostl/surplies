class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.10.1"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.10.1/surplies-v0.10.1-darwin-arm64.tar.gz"
    sha256 "c135deee407d4437f4c5fe6bfdb9c9d31660511bebbf2425b372491ae256da8d"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.10.1/surplies-v0.10.1-darwin-amd64.tar.gz"
    sha256 "6cfbd94366c43e2d63377289f7ae750d0aafa32c47381a119f41361d19ec2867"
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
