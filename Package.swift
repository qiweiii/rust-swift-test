// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
	name: "Bandersnatch",
	platforms: [
		.macOS(.v14)
	],
	products: [
		// Products define the executables and libraries a package produces, making them visible to other packages.
		// .library(
		// 	name: "Bandersnatch",
		// 	targets: ["Bandersnatch"]
		// )
	],
	dependencies: [],
	targets: [
		// Targets are the basic building blocks of a package, defining a module or a test suite.
		// Targets can depend on other targets in this package and products from dependencies.
		.target(
			name: "bandersnatch_vrfs",
			dependencies: [],
			path: "./",
			sources: [],
			publicHeadersPath: "./include",
			cSettings: [
				.headerSearchPath("./include")
			],
			linkerSettings: [
				.unsafeFlags([
					"-L./lib",
					"-lbandersnatch_vrfs",
				])
			]
		),
		.testTarget(
			name: "BandersnatchTests",
			dependencies: [
				"bandersnatch_vrfs"
			]
		),
	],
	swiftLanguageVersions: [.version("6")]
)
