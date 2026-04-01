class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.2.0"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.2.0/surplies-v0.2.0-darwin-arm64.tar.gz"
    sha256 "bdc410aadcd6d37286d985b6a09bf8ca96c0c5c7dfdd2f67c2d3a5488619e796"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.2.0/surplies-v0.2.0-darwin-amd64.tar.gz"
    sha256 "2eddbc2aa30c4084a7656c231fa47ee5e84022bc60d81dd9efe3eca2de16af3a"
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
