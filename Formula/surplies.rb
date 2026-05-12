class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.3.0"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.3.0/surplies-v0.3.0-darwin-arm64.tar.gz"
    sha256 "b37011e0ecb414cc0b19c20b806d951e067e5d9885e49f071d9957fcb108aebb"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.3.0/surplies-v0.3.0-darwin-amd64.tar.gz"
    sha256 "f16c1402888776e7c2cee36405c549549c328eb9bbb541439533b0874cb1d1c6"
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
