class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.1.0"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.1.0/surplies-v0.1.0-darwin-arm64.tar.gz"
    sha256 "901832f43487a463288b4e45fbb72ed3c111c50d110b0ada32435986975c5787"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.1.0/surplies-v0.1.0-darwin-amd64.tar.gz"
    sha256 "24436c1ce74469259a862eabf708b736699d9a18be2b00ada3cf4bfddb0b872d"
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
