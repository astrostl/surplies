class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.6.0"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.6.0/surplies-v0.6.0-darwin-arm64.tar.gz"
    sha256 "7358d60d1c06e1f84910c23fe02140f1276751629ed4d007df1e53a6d5842e77"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.6.0/surplies-v0.6.0-darwin-amd64.tar.gz"
    sha256 "d4b40a553576e347b59f990b7a3510847688e18ec96d5418b454e29af8d35c4a"
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
