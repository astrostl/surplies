class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.9.3"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.9.3/surplies-v0.9.3-darwin-arm64.tar.gz"
    sha256 "dfcd717c34279d129b1ca3b155e5f68460f6eb4c1cee9c235b91c712f75db5ac"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.9.3/surplies-v0.9.3-darwin-amd64.tar.gz"
    sha256 "ee86605771413c33907c1a9e4aced6906f027dd3fa6b820c09618f43c24abdf6"
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
