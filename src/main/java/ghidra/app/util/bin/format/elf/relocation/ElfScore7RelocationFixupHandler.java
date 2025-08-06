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
package ghidra.app.util.bin.format.elf.relocation;

import ghidra.app.plugin.core.reloc.ElfRelocationFixupHandler;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.util.CodeUnitInsertionException;

public class ElfScore7RelocationFixupHandler extends ElfRelocationFixupHandler {

	public ElfScore7RelocationFixupHandler() {
		super(Score7_ElfRelocationType.class);
	}

	@Override
	public boolean processRelocation(Program program, Relocation relocation, Address oldImageBase,
			Address newImageBase) throws MemoryAccessException, CodeUnitInsertionException {

		if (relocation.getStatus() != Status.APPLIED) {
			return false;
		}

		Score7_ElfRelocationType type =
			(Score7_ElfRelocationType) getRelocationType(relocation.getType());
		if (type == null) {
			return false;
		}

		switch (type) {
			case R_SCORE_HI16:
			case R_SCORE_LO16:
			case R_SCORE_BCMP:
			case R_SCORE_24:
			case R_SCORE_PC19:
			case R_SCORE16_11:
			case R_SCORE16_PC8:
			case R_SCORE_ABS32:
			case R_SCORE_ABS16:
			case R_SCORE_DUMMY2:
			case R_SCORE_GP15:
			case R_SCORE_GNU_VTINHERIT:
			case R_SCORE_GNU_VTENTRY:
			case R_SCORE_GOT15:
			case R_SCORE_GOT_LO16:
			case R_SCORE_CALL15:
			case R_SCORE_GPREL32:
			case R_SCORE_REL32:
			case R_SCORE_DUMMY_HI16:
			case R_SCORE_IMM30:
			case R_SCORE_IMM32:
				return process32BitRelocation(program, relocation, oldImageBase, newImageBase);
			default:
				return false;
		}
	}

	@Override
	public boolean handlesProgram(Program program) {
		if (!ElfLoader.ELF_NAME.equals(program.getExecutableFormat())) {
			return false;
		}
		Language language = program.getLanguage();
		if (language.getLanguageDescription().getSize() != 32) {
			return false;
		}
		Processor processor = language.getProcessor();
		return (processor.equals(Processor.findOrPossiblyCreateProcessor("Score7")));
	}
}
