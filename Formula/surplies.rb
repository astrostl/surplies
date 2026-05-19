class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.5.0"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.5.0/surplies-v0.5.0-darwin-arm64.tar.gz"
    sha256 "1557379645caffb208f850dc780b7f0cbd26383a0ea722c9cd53877d01448b24"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.5.0/surplies-v0.5.0-darwin-amd64.tar.gz"
    sha256 "5f493340cb1430bb366e904756fe7e02f4fc99c5bd72de22f45d56a533b31a52"
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
