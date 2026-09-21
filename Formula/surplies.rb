class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.11.5"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.11.5/surplies-v0.11.5-darwin-arm64.tar.gz"
    sha256 "27ea94c87dc8f6575032c526619a13c35ee71a430fac9cdb59478271cdd2bfee"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.11.5/surplies-v0.11.5-darwin-amd64.tar.gz"
    sha256 "1bc5bc3991f0ff1320bdce22a67547ee74ea38b1e23d795c51019bd7e6e19e43"
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
