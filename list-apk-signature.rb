#!/usr/bin/ruby

# Copyright 2022 hidenorly
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require './StrUtil'
require './ExecUtil'
require './FileUtil'
require 'optparse'
require 'shellwords'

class SignatureUtil
	def self.getSignatureFingerprint(path, useSHA256=false)
		result = nil

		if File.exist?(path) then
			exec_cmd = "keytool -printcert"
			if path.end_with?(".pem") then
				exec_cmd = "#{exec_cmd} -file #{Shellwords.escape(path)}"
			else
				exec_cmd = "#{exec_cmd} -jarfile #{Shellwords.escape(path)}"
			end
			if useSHA256 then
				exec_cmd = "#{exec_cmd} | grep \"SHA256:\""
			else
				exec_cmd = "#{exec_cmd} | grep \"SHA1:\""
			end
			fingerprint = ExecUtil.getExecResultEachLine(exec_cmd)
			fingerprint = fingerprint.length ? fingerprint[0].to_s : ""
			pos = fingerprint.index(":")
			if pos then
				fingerprint = fingerprint[pos+1..fingerprint.length]
			end
			fingerprint.strip!
			result = fingerprint.empty? ? nil : fingerprint
		end

		return result
	end

	def self._removeExt(path, ext)
		pos = path.rindex(ext)
		if pos then
			path = path[0..pos-1]
		end
		return path
	end

	def self.getSignaturesMap(signPaths, useSHA256)
		signMaps={}

		signPaths.each do |aPemPath|
			fingerprint = SignatureUtil.getSignatureFingerprint( aPemPath, useSHA256)
			if fingerprint then
				pemName = FileUtil.getFilenameFromPath( aPemPath )
				pemName = _removeExt(pemName, ".pem")
				pemName = _removeExt(pemName, ".x509")

				signMaps[ fingerprint ] = pemName
			end
		end

		return signMaps
	end
end


options = {
	:pemFolder => nil,
	:useSHA256 => true,
	:mode => "per-file",
	:verbose => false
}

opt_parser = OptionParser.new do |opts|
	opts.banner = "Usage: an apkFile or folder storing apks"

	opts.on("-p", "--pemFolder=", "Specify .pem file folder (You can specify multiple paths with ,)") do |pemFolder|
		options[:pemFolder] = pemFolder
	end

	opts.on("-s", "--useSHA128", "Use SHA128 fingerprint instead of SHA256") do
		options[:useSHA256] = false
	end

	opts.on("-m", "--mode=", "Output mode:per-signature or per-file default:#{options[:mode]}") do |mode|
		options[:mode] = mode
	end

	opts.on("-v", "--verbose", "Enable verbose status output (default:#{options[:verbose]})") do
		options[:verbose] = true
	end
end.parse!

if !ARGV.length && !options[:listFingerprintName] then
	puts "Specify apkPath or Folder of APKs"
	exit(-1)
end

# Create map of pemfile name and the fingerprint
signPaths = []
if nil!=options[:pemFolder] then
	pemFolders = options[:pemFolder].to_s.split(",")
	pemFolders.each do |aPemFolder|
		signs = FileUtil.getSpecifiedFiles(aPemFolder.strip, "\.pem$")
		signPaths.concat(signs)
	end
	signPaths.uniq!
end
puts signPaths if options[:verbose]
signMaps = SignatureUtil.getSignaturesMap(signPaths, options[:useSHA256])

# Enumerate apks
apkPaths = []
apkFolders = ARGV[0].to_s.split(",")
apkFolders.each do |anApkFolder|
	result = FileUtil.getSpecifiedFiles(anApkFolder.strip, "\.(apk|jar)$")
	apkPaths.concat(result)
end
apkPaths.uniq!

if !apkPaths.length then
	puts "Specify apkPath or Folder of APKs"
	exit(-1)
end

if apkPaths.length then
	# Get apk/jar's fingerprint
	apkSignatureFingerPrints={}
	apkPaths.each do |anApkPath|
		apkSignatureFingerPrints[ anApkPath ] = SignatureUtil.getSignatureFingerprint( anApkPath, options[:useSHA256])
	end

	reportSignatureApk = {}

	apkSignatureFingerPrints.each do |apkName, fingerprint|
		orgFingerprint = fingerprint
		apkName = FileUtil.getFilenameFromPath(apkName) if !options[:verbose]
		fingerprint = signMaps[fingerprint] if signMaps.has_key?(fingerprint)

		if options[:verbose] then
			puts "#{apkName}:#{fingerprint}"
		end

		fingerprint = fingerprint ? fingerprint : orgFingerprint
		reportSignatureApk[fingerprint] = [] if !reportSignatureApk.has_key?(fingerprint)
		reportSignatureApk[fingerprint] << apkName
	end

	# Output apk/jar's fingerprint
	reportSignatureApk.each do |sign, apks|
		case options[:mode]
		when "per-signature"
			apkNames = ""
			apks.each do |anApk|
				apkNames = apkNames.empty? ? "\"#{anApk}\"" : "\"#{anApk}\", #{apkNames}"
			end
			apkNames = apks.length >=2 ? "[ #{apkNames} ]" : apkNames
			puts "{ \"#{sign}\" : #{apkNames} },"
		else
			apks.each do |anApk|
				puts "{ \"#{sign}\" : \"#{anApk}\" },"
			end
		end
	end
end