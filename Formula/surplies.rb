class Surplies < Formula
  desc "Scans for supply chain attack IOCs (axios, litellm, mini-shai-hulud) via filesystem-only detection"
  homepage "https://github.com/astrostl/surplies"
  version "v0.8.2"
  license "MIT"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/astrostl/surplies/releases/download/v0.8.2/surplies-v0.8.2-darwin-arm64.tar.gz"
    sha256 "d8aefe15d6ca55edc9d467512370930414efbbd7d7d215ccc42a5c3a915ede56"
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/astrostl/surplies/releases/download/v0.8.2/surplies-v0.8.2-darwin-amd64.tar.gz"
    sha256 "80e376b9fda618e66b7cf91beb23e020a62e7e553fd650cb3becbbea450b1210"
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
