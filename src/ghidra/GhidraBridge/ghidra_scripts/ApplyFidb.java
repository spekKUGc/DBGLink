/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Attaches Function ID databases (.fidb) before headless analysis so the
// built-in "Function ID" analyzer applies them to the imported program.
// The launcher (DBGLINK_FIDB) runs this as "-preScript ApplyFidb.java <spec>".
// <spec> is one .fidb file or directory, or several entries separated with
// ';'. Headless splits script arguments on spaces, so entries containing
// spaces are rejoined here and only ';' separates them.
//@category FunctionID
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;

public class ApplyFidb extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length == 0) {
			printerr("ApplyFidb: no Function ID database path supplied; skipping.");
			return;
		}
		List<File> candidates = new ArrayList<>();
		for (String entry : String.join(" ", args).split(";")) {
			String trimmed = entry.trim();
			if (trimmed.isEmpty()) {
				continue;
			}
			collectCandidates(new File(trimmed), candidates);
		}

		FidFileManager manager = FidFileManager.getInstance();
		int attached = 0;
		for (File candidate : candidates) {
			try {
				FidFile attachedFile = manager.addUserFidFile(candidate);
				if (attachedFile != null) {
					// Already-attached files come back as the existing FidFile;
					// freshly added valid ones as the new FidFile.
					attached++;
					println("ApplyFidb: attached " + candidate.getAbsolutePath());
				}
				else {
					// Null means the file is not a valid FID database (the
					// manager only returns null for invalid files).
					printerr("ApplyFidb: not a valid Function ID database, skipping: " +
						candidate.getAbsolutePath());
				}
			}
			catch (Exception e) {
				printerr("ApplyFidb: failed to attach " + candidate.getAbsolutePath() +
					": " + e.getMessage());
			}
		}
		if (attached == 0) {
			printerr("ApplyFidb: no Function ID databases attached.");
		}
	}

	private void collectCandidates(File entry, List<File> candidates) {
		if (entry.isDirectory()) {
			File[] packed = entry.listFiles((dir, name) -> {
				String lower = name.toLowerCase();
				return lower.endsWith(FidFile.FID_PACKED_DATABASE_FILE_EXTENSION) ||
					lower.endsWith(FidFile.FID_RAW_DATABASE_FILE_EXTENSION);
			});
			if (packed == null || packed.length == 0) {
				printerr("ApplyFidb: no .fidb files in directory: " + entry.getAbsolutePath());
				return;
			}
			Arrays.sort(packed);
			candidates.addAll(Arrays.asList(packed));
		}
		else if (entry.isFile()) {
			candidates.add(entry);
		}
		else {
			printerr("ApplyFidb: not found, skipping: " + entry.getPath());
		}
	}
}
