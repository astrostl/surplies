class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.5.1"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.5.1/surplies-v0.5.1-darwin-arm64.tar.gz"
    sha256 "0be30915d71335d046f4f2c47f99c30f601b682a32729d74f2ca317be8c0a55f"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.5.1/surplies-v0.5.1-darwin-amd64.tar.gz"
    sha256 "11951a29a2f5480cf318efc9227f0f62dc04cdee3313da1e1f7b27c1322c6a05"
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
