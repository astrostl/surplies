class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.8.1"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.8.1/surplies-v0.8.1-darwin-arm64.tar.gz"
    sha256 "954e063919cd20082ec98f15302d5836ca0626b648d138c2f692b38a951b258f"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.8.1/surplies-v0.8.1-darwin-amd64.tar.gz"
    sha256 "74177d5ce312cfe1a1de7258af1806c3b05c806d6f4c3ef955439919f90dc88e"
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
