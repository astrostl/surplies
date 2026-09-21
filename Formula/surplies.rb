class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.11.4"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.11.4/surplies-v0.11.4-darwin-arm64.tar.gz"
    sha256 "fb74829edb207a838b6c6c36d6ac155d4e461a351dffc9ed3c8684786a0b09b1"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.11.4/surplies-v0.11.4-darwin-amd64.tar.gz"
    sha256 "b1e1acdaee2d3bd12f3cfebb7da1cd1dd0942e3217b882f6559fe54a7351a384"
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
