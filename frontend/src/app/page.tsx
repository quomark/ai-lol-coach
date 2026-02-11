import ReplayUploader from "@/components/ReplayUploader";

export default function Home() {
  return (
    <main className="mx-auto max-w-5xl px-4 py-12">
      {/* Header */}
      <div className="mb-12 text-center">
        <h1 className="bg-gradient-to-r from-blue-400 via-indigo-400 to-purple-400 bg-clip-text text-5xl font-black tracking-tight text-transparent">
          AI LoL Coach
        </h1>
        <p className="mt-3 text-lg text-gray-400">
          Upload your replay. Get real coaching advice.
        </p>
        <div className="mt-4 flex items-center justify-center gap-6 text-sm text-gray-500">
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-emerald-500" />
            Upload .rofl
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-blue-500" />
            AI Analysis
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-purple-500" />
            Get Better
          </span>
        </div>
      </div>

      {/* Upload + Results */}
      <ReplayUploader />

      {/* Footer info */}
      <div className="mt-16 text-center text-sm text-gray-600">
        <p>
          Powered by fine-tuned AI models trained on League of Legends replay
          data
        </p>
        <p className="mt-1">
          .rofl files are found in:{" "}
          <code className="rounded bg-gray-800 px-2 py-0.5 text-gray-400">
            C:\Users\YOU\Documents\League of Legends\Replays
          </code>
        </p>
      </div>
    </main>
  );
}
