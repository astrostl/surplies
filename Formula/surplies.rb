class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.4.0"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.4.0/surplies-v0.4.0-darwin-arm64.tar.gz"
    sha256 "a7836ef3e8156865429776373c5111127b8a9a137cae2170f8e18ab2f77c05d7"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.4.0/surplies-v0.4.0-darwin-amd64.tar.gz"
    sha256 "f9a0364726ef19a4be0181c5b69313b7cf41b0541225cf55f4a0324663d0911d"
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
