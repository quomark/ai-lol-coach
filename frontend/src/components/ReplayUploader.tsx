"use client";

import { useState, useCallback } from "react";
import { Upload, Loader2, X } from "lucide-react";

interface PlayerSummary {
  champion: string;
  summoner_name: string;
  team: string;
  role: string;
  kda: string;
  cs: number;
  gold: number;
  damage_dealt: number;
  vision_score: number;
}

interface CoachingResult {
  game_summary: string;
  players: PlayerSummary[];
  coaching_advice: string;
  focus_player: string | null;
  strengths: string[];
  weaknesses: string[];
  actionable_tips: string[];
}

export default function ReplayUploader() {
  const [file, setFile] = useState<File | null>(null);
  const [summonerName, setSummonerName] = useState("");
  const [focusAreas, setFocusAreas] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<CoachingResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const dropped = e.dataTransfer.files[0];
    if (dropped?.name.endsWith(".rofl")) {
      setFile(dropped);
      setError(null);
    } else {
      setError("Please drop a .rofl replay file");
    }
  }, []);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selected = e.target.files?.[0];
    if (selected) {
      setFile(selected);
      setError(null);
    }
  };

  const handleSubmit = async () => {
    if (!file) return;

    setLoading(true);
    setError(null);
    setResult(null);

    const formData = new FormData();
    formData.append("file", file);
    if (summonerName) formData.append("summoner_name", summonerName);
    if (focusAreas) formData.append("focus_areas", focusAreas);

    try {
      const res = await fetch("/api/replay/upload", {
        method: "POST",
        body: formData,
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || "Upload failed");
      }

      const data: CoachingResult = await res.json();
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Upload zone */}
      <div
        onDrop={handleDrop}
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        className={`relative rounded-2xl border-2 border-dashed p-12 text-center transition-all ${
          dragOver
            ? "border-blue-400 bg-blue-500/10"
            : file
              ? "border-emerald-500/50 bg-emerald-500/5"
              : "border-gray-700 bg-gray-900/50 hover:border-gray-500"
        }`}
      >
        <input
          type="file"
          accept=".rofl"
          onChange={handleFileSelect}
          className="absolute inset-0 cursor-pointer opacity-0"
        />
        {file ? (
          <div className="flex items-center justify-center gap-3">
            <div className="rounded-lg bg-emerald-500/20 p-3">
              <Upload className="h-6 w-6 text-emerald-400" />
            </div>
            <div className="text-left">
              <p className="font-medium text-emerald-300">{file.name}</p>
              <p className="text-sm text-gray-400">
                {(file.size / 1024 / 1024).toFixed(1)} MB
              </p>
            </div>
            <button
              onClick={(e) => {
                e.stopPropagation();
                setFile(null);
                setResult(null);
              }}
              className="ml-4 rounded-lg p-2 text-gray-400 hover:bg-gray-800 hover:text-gray-200"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        ) : (
          <div>
            <Upload className="mx-auto h-12 w-12 text-gray-500" />
            <p className="mt-4 text-lg font-medium text-gray-300">
              Drop your .rofl replay file here
            </p>
            <p className="mt-1 text-sm text-gray-500">or click to browse</p>
          </div>
        )}
      </div>

      {/* Options */}
      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <label className="mb-2 block text-sm font-medium text-gray-400">
            Summoner Name (optional)
          </label>
          <input
            type="text"
            value={summonerName}
            onChange={(e) => setSummonerName(e.target.value)}
            placeholder="Focus analysis on this player"
            className="w-full rounded-xl border border-gray-700 bg-gray-900/80 px-4 py-3 text-gray-100 placeholder-gray-600 outline-none transition focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
        </div>
        <div>
          <label className="mb-2 block text-sm font-medium text-gray-400">
            Focus Areas (optional)
          </label>
          <input
            type="text"
            value={focusAreas}
            onChange={(e) => setFocusAreas(e.target.value)}
            placeholder="e.g. vision, cs, macro, teamfighting"
            className="w-full rounded-xl border border-gray-700 bg-gray-900/80 px-4 py-3 text-gray-100 placeholder-gray-600 outline-none transition focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
        </div>
      </div>

      {/* Submit */}
      <button
        onClick={handleSubmit}
        disabled={!file || loading}
        className="w-full rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 px-6 py-4 text-lg font-semibold text-white shadow-lg shadow-blue-500/25 transition-all hover:from-blue-500 hover:to-indigo-500 hover:shadow-blue-500/40 disabled:cursor-not-allowed disabled:opacity-50 disabled:shadow-none"
      >
        {loading ? (
          <span className="flex items-center justify-center gap-2">
            <Loader2 className="h-5 w-5 animate-spin" />
            Analyzing replay...
          </span>
        ) : (
          "Analyze Replay"
        )}
      </button>

      {/* Error */}
      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-500/10 px-6 py-4 text-red-300">
          {error}
        </div>
      )}

      {/* Results */}
      {result && <CoachingResults result={result} />}
    </div>
  );
}

function CoachingResults({ result }: { result: CoachingResult }) {
  return (
    <div className="space-y-6">
      {/* Game Summary */}
      <div className="rounded-2xl border border-gray-800 bg-gray-900/60 p-6">
        <h2 className="mb-3 text-xl font-bold text-white">Game Summary</h2>
        <p className="text-gray-300">{result.game_summary}</p>
        {result.focus_player && (
          <p className="mt-2 text-sm text-blue-400">
            Focused on: {result.focus_player}
          </p>
        )}
      </div>

      {/* Scoreboard */}
      <div className="rounded-2xl border border-gray-800 bg-gray-900/60 p-6">
        <h2 className="mb-4 text-xl font-bold text-white">Scoreboard</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700 text-left text-gray-400">
                <th className="pb-3 pr-4">Player</th>
                <th className="pb-3 pr-4">Champion</th>
                <th className="pb-3 pr-4">Role</th>
                <th className="pb-3 pr-4">KDA</th>
                <th className="pb-3 pr-4">CS</th>
                <th className="pb-3 pr-4">Gold</th>
                <th className="pb-3 pr-4">Damage</th>
                <th className="pb-3">Vision</th>
              </tr>
            </thead>
            <tbody>
              {["Blue", "Red"].map((team) => (
                <>
                  <tr key={team}>
                    <td
                      colSpan={8}
                      className={`pt-4 pb-2 text-xs font-bold uppercase tracking-wider ${
                        team === "Blue" ? "text-blue-400" : "text-red-400"
                      }`}
                    >
                      {team} Team
                    </td>
                  </tr>
                  {result.players
                    .filter((p) => p.team === team)
                    .map((p) => (
                      <tr
                        key={p.summoner_name}
                        className={`border-b border-gray-800/50 ${
                          p.summoner_name === result.focus_player
                            ? "bg-blue-500/10"
                            : ""
                        }`}
                      >
                        <td className="py-2 pr-4 font-medium text-gray-200">
                          {p.summoner_name}
                        </td>
                        <td className="py-2 pr-4 text-gray-300">
                          {p.champion}
                        </td>
                        <td className="py-2 pr-4 text-gray-400">{p.role}</td>
                        <td className="py-2 pr-4 font-mono text-gray-200">
                          {p.kda}
                        </td>
                        <td className="py-2 pr-4 font-mono text-gray-300">
                          {p.cs}
                        </td>
                        <td className="py-2 pr-4 font-mono text-yellow-300">
                          {p.gold.toLocaleString()}
                        </td>
                        <td className="py-2 pr-4 font-mono text-orange-300">
                          {p.damage_dealt.toLocaleString()}
                        </td>
                        <td className="py-2 font-mono text-cyan-300">
                          {p.vision_score.toFixed(0)}
                        </td>
                      </tr>
                    ))}
                </>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Strengths & Weaknesses */}
      <div className="grid gap-6 md:grid-cols-2">
        <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/5 p-6">
          <h3 className="mb-3 text-lg font-bold text-emerald-400">
            ✓ Strengths
          </h3>
          <ul className="space-y-2">
            {result.strengths.map((s, i) => (
              <li key={i} className="text-gray-300">
                {s}
              </li>
            ))}
          </ul>
        </div>
        <div className="rounded-2xl border border-red-500/20 bg-red-500/5 p-6">
          <h3 className="mb-3 text-lg font-bold text-red-400">
            ✗ Weaknesses
          </h3>
          <ul className="space-y-2">
            {result.weaknesses.map((w, i) => (
              <li key={i} className="text-gray-300">
                {w}
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* Actionable Tips */}
      {result.actionable_tips.length > 0 && (
        <div className="rounded-2xl border border-blue-500/20 bg-blue-500/5 p-6">
          <h3 className="mb-4 text-lg font-bold text-blue-400">
            Actionable Tips
          </h3>
          <div className="space-y-3">
            {result.actionable_tips.map((tip, i) => (
              <div key={i} className="flex gap-3">
                <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-blue-500/20 text-sm font-bold text-blue-400">
                  {i + 1}
                </span>
                <p className="text-gray-300">{tip}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Full coaching advice */}
      {result.coaching_advice && (
        <div className="rounded-2xl border border-gray-800 bg-gray-900/60 p-6">
          <h3 className="mb-3 text-lg font-bold text-white">
            Detailed Analysis
          </h3>
          <div className="whitespace-pre-wrap text-gray-300">
            {result.coaching_advice}
          </div>
        </div>
      )}
    </div>
  );
}
