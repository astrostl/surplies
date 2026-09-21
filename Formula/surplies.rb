class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.13.1"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.13.1/surplies-v0.13.1-darwin-arm64.tar.gz"
    sha256 "80aeab3f23829886d1e130454f20d249c282a572ea3645e641251ca4ac5e72e2"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.13.1/surplies-v0.13.1-darwin-amd64.tar.gz"
    sha256 "9f7bec0277fdbdf24576b244aabba69f8a4e763b5211cfa41eec14f4ff9fb9c4"
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
