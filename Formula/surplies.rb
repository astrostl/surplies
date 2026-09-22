class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.14.1"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.14.1/surplies-v0.14.1-darwin-arm64.tar.gz"
    sha256 "9429a324b4b0771719372d7aa4c1c18db1832d977a7cf2bf61408998f657db4a"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.14.1/surplies-v0.14.1-darwin-amd64.tar.gz"
    sha256 "0441230e7ca77d872e671b0236a39d6125e70bd2e10684111e2a11204aba03ee"
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
