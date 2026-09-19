class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.9.4"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.9.4/surplies-v0.9.4-darwin-arm64.tar.gz"
    sha256 "aae970fef15f0fde344d43f20f23767e7853774533a8394cd637ec673d944734"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.9.4/surplies-v0.9.4-darwin-amd64.tar.gz"
    sha256 "2aa22f57b74d28fdf2fab4bfbfc644526dc50456502a93c48f188d56e9a8ec54"
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
