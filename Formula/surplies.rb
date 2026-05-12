class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.4.1"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.4.1/surplies-v0.4.1-darwin-arm64.tar.gz"
    sha256 "e670340e307a36bdb9a1707d6d9346a0d5e94f9a83387a2e361e2a42628fe5a4"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.4.1/surplies-v0.4.1-darwin-amd64.tar.gz"
    sha256 "2d3c7f6e5cd0802bc0278909f6490bb0364d747287311b60f6b6bb3a89f04be8"
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
