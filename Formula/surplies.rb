class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.13.0"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.13.0/surplies-v0.13.0-darwin-arm64.tar.gz"
    sha256 "fa21d7ffcf9d7b663092d1396c543719e6660d857a7034e0965cf24841efaf91"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.13.0/surplies-v0.13.0-darwin-amd64.tar.gz"
    sha256 "fb16c95fb7116c392513b3d4a0341046aa45998cb115cbce15fa33f3fdd7ce80"
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
