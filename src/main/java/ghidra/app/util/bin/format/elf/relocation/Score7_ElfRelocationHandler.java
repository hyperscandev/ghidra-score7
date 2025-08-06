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

import java.util.Map;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;

public class Score7_ElfRelocationHandler
		extends AbstractElfRelocationHandler<Score7_ElfRelocationType, ElfRelocationContext<?>> {

	/* Old Sunplus S+core7 backend magic number. Written in the absence of an ABI.  */
	final long EM_SCORE_OLD = 95;

	/**
	 * Constructor
	 */
	public Score7_ElfRelocationHandler() {
		super(Score7_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == ElfConstants.EM_SCORE7 || elf.e_machine() == EM_SCORE_OLD;
	}

	@Override
	protected RelocationResult relocate(ElfRelocationContext<?> elfRelocationContext,
			ElfRelocation relocation, Score7_ElfRelocationType type, Address relocationAddress,
			ElfSymbol sym, Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		boolean instructionBigEndian =
			program.getLanguage().getLanguageDescription().getInstructionEndian().isBigEndian();

		long addend = relocation.getAddend(); // will be 0 for REL case

		long offset = Integer.toUnsignedLong((int) relocationAddress.getOffset());
		int symbolIndex = relocation.getSymbolIndex();
		int byteLength = 4; // most relocations affect 4-bytes (change if different)

		if (type == Score7_ElfRelocationType.R_SCORE_NONE)
			return RelocationResult.SKIPPED;

		switch (type) {
			case R_SCORE_HI16:
			case R_SCORE_LO16: {
				int oldValue = memory.getInt(relocationAddress);

				int oldAddr = ((oldValue & 0x00007ffe) >> 1) | ((oldValue & 0x00030000) >> 2);
				int newValue = (int) (oldAddr + symbolValue + addend);
				if (type == Score7_ElfRelocationType.R_SCORE_HI16)
					newValue >>= 16;

				int sValue = (oldValue & 0xfffc8001) | ((newValue & 0x00003fff) << 1) | ((newValue & 0x0000c000) << 2);
				memory.setInt(relocationAddress, sValue);
				break;
			}
			case R_SCORE_24: {
				int oldValue = memory.getInt(relocationAddress);
				int oldAddr = ((oldValue & 0x03ff0000) >> 1) | (oldValue & 0x00007ffe);
				int newValue = (int) (oldAddr + addend + symbolValue) >> 1;

				int sValue = (oldValue & 0xfc008001) | ((newValue & 0x00003fff) << 1) | ((newValue & 0x00ffc000) << 2);
				memory.setInt(relocationAddress, sValue);
				break;
			}
			case R_SCORE_ABS32: {
				int oldValue = memory.getInt(relocationAddress);
				int sValue = (int) (oldValue + symbolValue - addend);
				memory.setInt(relocationAddress, sValue);
				break;
			}
			case R_SCORE_GP15: {
				int oldValue = memory.getInt(relocationAddress);
				int oldAddr = oldValue & 0x00007fff;

				if ((oldAddr & 0x4000) != 0)    // sign extend
					oldAddr = -(oldAddr ^ 0x7fff) - 1;

				int newValue = (int) (oldAddr + symbolValue - addend);

				int sValue = (oldValue & 0xffff8000) | (newValue & 0x00007fff);
				memory.setInt(relocationAddress, sValue);
				break;
			}

			//case R_SCORE_BCMP:
			//case R_SCORE_PC19:
			//case R_SCORE16_11:
			//case R_SCORE16_PC8:
			//case R_SCORE_ABS16:
			//case R_SCORE_DUMMY2:
			//case R_SCORE_GNU_VTINHERIT:
			//case R_SCORE_GNU_VTENTRY:
			//case R_SCORE_GOT15:
			//case R_SCORE_GOT_LO16:
			//case R_SCORE_CALL15:
			//case R_SCORE_GPREL32:
			//case R_SCORE_REL32:
			//case R_SCORE_DUMMY_HI16:
			//case R_SCORE_IMM30:
			//case R_SCORE_IMM32:

			default: {
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
			}
		}

		return new RelocationResult(Status.APPLIED, byteLength);
	}
}
