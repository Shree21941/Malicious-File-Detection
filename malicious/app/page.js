'use client';
import React, { useState } from 'react';
import { Upload, FileText, AlertCircle, CheckCircle, Loader2, Shield, XCircle } from 'lucide-react';

export default function MalwareDetectionSystem() {
  const [file, setFile] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    if (selectedFile) {
      const fileType = selectedFile.name.toLowerCase();
      if (fileType.endsWith('.pdf') || fileType.endsWith('.exe') || fileType.endsWith('.dll')) {
        setFile(selectedFile);
        setError(null);
        setResult(null);
      } else {
        setError('Please upload a PDF or PE file (.exe, .dll)');
        setFile(null);
      }
    }
  };

  const handleScan = async () => {
    if (!file) return;

    setScanning(true);
    setError(null);
    setResult(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        body: formData,
      });

      const data = await response.json();

      if (response.ok) {
        setResult(data);
      } else {
        setError(data.error || 'Scan failed');
      }
    } catch (err) {
      setError('Connection error. Make sure the backend is running.');
    } finally {
      setScanning(false);
    }
  };

  const getThreatLevel = (probability) => {
    if (probability >= 0.8) return { level: 'Critical', color: 'text-red-600', bg: 'bg-red-50', border: 'border-red-200' };
    if (probability >= 0.6) return { level: 'High', color: 'text-orange-600', bg: 'bg-orange-50', border: 'border-orange-200' };
    if (probability >= 0.4) return { level: 'Medium', color: 'text-yellow-600', bg: 'bg-yellow-50', border: 'border-yellow-200' };
    if (probability >= 0.2) return { level: 'Low', color: 'text-blue-600', bg: 'bg-blue-50', border: 'border-blue-200' };
    return { level: 'Clean', color: 'text-green-600', bg: 'bg-green-50', border: 'border-green-200' };
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 p-6">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <Shield className="w-16 h-16 text-blue-400" />
          </div>
          <h1 className="text-4xl font-bold text-white mb-2">Malware Detection System</h1>
          <p className="text-blue-200">Advanced PDF & PE Binary Analysis</p>
        </div>

        {/* Upload Card */}
        <div className="bg-white rounded-xl shadow-2xl p-8 mb-6">
          <div className="mb-6">
            <label className="block text-sm font-semibold text-gray-700 mb-3">
              Upload File for Analysis
            </label>
            <div className="flex items-center gap-4">
              <label className="flex-1 flex items-center justify-center px-6 py-4 border-2 border-dashed border-gray-300 rounded-lg cursor-pointer hover:border-blue-500 hover:bg-blue-50 transition-all">
                <Upload className="w-6 h-6 text-gray-400 mr-3" />
                <span className="text-sm text-gray-600">
                  {file ? file.name : 'Choose PDF or PE file'}
                </span>
                <input
                  type="file"
                  className="hidden"
                  onChange={handleFileChange}
                  accept=".pdf,.exe,.dll"
                />
              </label>
              <button
                onClick={handleScan}
                disabled={!file || scanning}
                className="px-8 py-4 bg-blue-600 text-white rounded-lg font-semibold hover:bg-blue-700 disabled:bg-gray-300 disabled:cursor-not-allowed transition-all flex items-center gap-2"
              >
                {scanning ? (
                  <>
                    <Loader2 className="w-5 h-5 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Shield className="w-5 h-5" />
                    Scan File
                  </>
                )}
              </button>
            </div>
            <p className="text-xs text-gray-500 mt-2">
              Supported formats: PDF, EXE, DLL (Max 50MB)
            </p>
          </div>

          {/* Error Display */}
          {error && (
            <div className="flex items-start gap-3 p-4 bg-red-50 border border-red-200 rounded-lg">
              <XCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold text-red-800">Error</p>
                <p className="text-sm text-red-600">{error}</p>
              </div>
            </div>
          )}

          {/* Results Display */}
          {result && (
            <div className="space-y-4">
              <div className={`p-6 rounded-lg border-2 ${getThreatLevel(result.malicious_probability).bg} ${getThreatLevel(result.malicious_probability).border}`}>
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    {result.is_malicious ? (
                      <AlertCircle className={`w-8 h-8 ${getThreatLevel(result.malicious_probability).color}`} />
                    ) : (
                      <CheckCircle className="w-8 h-8 text-green-600" />
                    )}
                    <div>
                      <h3 className={`text-2xl font-bold ${getThreatLevel(result.malicious_probability).color}`}>
                        {result.is_malicious ? 'MALICIOUS DETECTED' : 'FILE CLEAN'}
                      </h3>
                      <p className="text-sm text-gray-600">
                        Threat Level: {getThreatLevel(result.malicious_probability).level}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className={`text-4xl font-bold ${getThreatLevel(result.malicious_probability).color}`}>
                      {(result.malicious_probability * 100).toFixed(1)}%
                    </div>
                    <div className="text-xs text-gray-600">Confidence</div>
                  </div>
                </div>

                {/* Progress Bar */}
                <div className="w-full bg-gray-200 rounded-full h-3 mb-4">
                  <div
                    className={`h-3 rounded-full ${result.malicious_probability >= 0.5 ? 'bg-red-600' : 'bg-green-600'}`}
                    style={{ width: `${result.malicious_probability * 100}%` }}
                  />
                </div>

                {/* File Info */}
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="font-semibold text-gray-700">File Name:</span>
                    <p className="text-gray-600 break-all">{result.filename}</p>
                  </div>
                  <div>
                    <span className="font-semibold text-gray-700">File Type:</span>
                    <p className="text-gray-600">{result.file_type}</p>
                  </div>
                  <div>
                    <span className="font-semibold text-gray-700">File Size:</span>
                    <p className="text-gray-600">{result.file_size}</p>
                  </div>
                  <div>
                    <span className="font-semibold text-gray-700">Scan Time:</span>
                    <p className="text-gray-600">{result.scan_time}</p>
                  </div>
                </div>
              </div>

              {/* Features Display */}
              {result.features && (
                <div className="bg-gray-50 p-6 rounded-lg border border-gray-200">
                  <h4 className="font-semibold text-gray-800 mb-3 flex items-center gap-2">
                    <FileText className="w-5 h-5" />
                    Extracted Features
                  </h4>
                  <div className="grid grid-cols-2 gap-3 text-sm">
                    {Object.entries(result.features).slice(0, 8).map(([key, value]) => (
                      <div key={key} className="flex justify-between">
                        <span className="text-gray-600">{key.replace(/_/g, ' ')}:</span>
                        <span className="font-mono text-gray-800">
                          {typeof value === 'number' ? value.toFixed(4) : value}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommendations */}
              <div className="bg-blue-50 p-4 rounded-lg border border-blue-200">
                <h4 className="font-semibold text-blue-900 mb-2">Recommendations</h4>
                <ul className="text-sm text-blue-800 space-y-1">
                  {result.is_malicious ? (
                    <>
                      <li>• Do not open or execute this file</li>
                      <li>• Quarantine the file immediately</li>
                      <li>• Report to your security team</li>
                      <li>• Scan your system with antivirus software</li>
                    </>
                  ) : (
                    <>
                      <li>• File appears safe based on analysis</li>
                      <li>• Always exercise caution with unknown files</li>
                      <li>• Keep your antivirus software updated</li>
                    </>
                  )}
                </ul>
              </div>
            </div>
          )}
        </div>

        {/* Info Footer */}
        <div className="text-center text-blue-200 text-sm">
          <p>Advanced machine learning models for malware detection</p>
          <p className="text-xs mt-1 text-blue-300">PDF Genome Analysis • PE Binary Analysis • Real-time Scanning</p>
        </div>
      </div>
    </div>
  );
}