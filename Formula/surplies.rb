class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.2.1"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.2.1/surplies-v0.2.1-darwin-arm64.tar.gz"
    sha256 "08fce173392df7cab309d84da635e41039761db0a525bf47280e7a27e564f05a"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.2.1/surplies-v0.2.1-darwin-amd64.tar.gz"
    sha256 "7fe4da1a72e3343f33a74c1cc562fb18bec228e64bb1a5b6c0b3902650032741"
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
