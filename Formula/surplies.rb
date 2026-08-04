class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.7.1"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.7.1/surplies-v0.7.1-darwin-arm64.tar.gz"
    sha256 "082f4250975254be03b425cafc998ee36e35ebc97b2655b12e639bda0e63f952"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.7.1/surplies-v0.7.1-darwin-amd64.tar.gz"
    sha256 "11a57a900fdb1ce533216c2177e11be7c2fdc5476bc3c256dfe8e11d7eba0dae"
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
