// screenpipe — AI that knows everything you've seen, said, or heard
// https://screenpipe.com

import CoreGraphics
import Foundation
import ImageIO
import Vision

struct NormalizedBounds: Encodable {
    let x: Double
    let y: Double
    let width: Double
    let height: Double
}

struct OCRObservation: Encodable {
    let text: String
    let confidence: Double
    let bounds: NormalizedBounds
}

struct OCRResult: Encodable {
    let recognitionLanguages: [String]
    let observations: [OCRObservation]
}

func fail(_ message: String) -> Never {
    let data = (message + "\n").data(using: .utf8) ?? Data()
    FileHandle.standardError.write(data)
    exit(2)
}

guard CommandLine.arguments.count == 2 else {
    fail("usage: vision_ocr.swift IMAGE.png")
}

let imagePath = CommandLine.arguments[1]
let imageURL = URL(fileURLWithPath: imagePath)
guard let imageSource = CGImageSourceCreateWithURL(imageURL as CFURL, nil),
      let image = CGImageSourceCreateImageAtIndex(imageSource, 0, nil) else {
    fail("cannot decode PNG image")
}

let languages = ["ja-JP", "en-US"]
let request = VNRecognizeTextRequest()
request.recognitionLevel = .accurate
request.recognitionLanguages = languages
request.usesLanguageCorrection = true

do {
    let handler = VNImageRequestHandler(cgImage: image, options: [:])
    try handler.perform([request])
} catch {
    fail("Vision OCR failed")
}

let observations = (request.results ?? []).compactMap { observation -> OCRObservation? in
    guard let candidate = observation.topCandidates(1).first else {
        return nil
    }
    let box = observation.boundingBox
    return OCRObservation(
        text: candidate.string,
        confidence: Double(candidate.confidence),
        bounds: NormalizedBounds(
            x: Double(box.origin.x),
            y: Double(box.origin.y),
            width: Double(box.size.width),
            height: Double(box.size.height)
        )
    )
}

let result = OCRResult(recognitionLanguages: languages, observations: observations)
let encoder = JSONEncoder()
encoder.outputFormatting = [.sortedKeys]
do {
    let data = try encoder.encode(result)
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write("\n".data(using: .utf8) ?? Data())
} catch {
    fail("cannot encode OCR result")
}
