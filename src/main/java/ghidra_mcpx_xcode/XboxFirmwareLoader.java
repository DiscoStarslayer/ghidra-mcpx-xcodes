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
package ghidra_mcpx_xcode;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Firmware Loader for properly setting up memory space and entry point for xbox firmware XCode
 */
public class XboxFirmwareLoader extends AbstractProgramWrapperLoader {

	@Override
	public String getName() {

		return "Xbox Firmware XCode Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		byte[] firmwareHeader = ByteBuffer.allocate(8).putInt(0x090000FF).putInt(0x080000FF).array();
		byte[] fileHeader = provider.readBytes(0, 8);
		
		if (Arrays.equals(firmwareHeader, fileHeader)) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("mcpxcode:LE:32:default", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		BinaryReader reader = new BinaryReader(provider, true).asLittleEndian();
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		
		Memory mem = program.getMemory();
		
		byte[] rom = reader.readByteArray(0, (int) reader.length());
		
		AddressSpace[] spaces = program.getAddressFactory().getAddressSpaces();
		
		
		try {
			MemoryBlock ram = mem.createInitializedBlock("ram", program.getAddressFactory().getAddressSpace(spaces[0].getSpaceID()).getAddress(0), 0x10000000, (byte)0x00, monitor, false);
			
			ram.setRead(true);
			ram.setWrite(true);
			ram.setExecute(true);
			ram.putBytes(api.toAddr(0x0), rom);
			
			MemoryBlock io = mem.createUninitializedBlock("io", program.getAddressFactory().getAddressSpace(spaces[1].getSpaceID()).getAddress(0), 0x10000, false);
			
			io.setRead(true);
			io.setWrite(true);
			io.setVolatile(true);
			
			MemoryBlock pciconf = mem.createUninitializedBlock("pciconf", program.getAddressFactory().getAddressSpace(spaces[2].getSpaceID()).getAddress(0x80000000), 0x2FFFFFFF, false);
			
			pciconf.setRead(true);
			pciconf.setWrite(true);
			pciconf.setVolatile(true);
			
			api.addEntryPoint(api.toAddr(0x80));			
			api.disassemble(api.toAddr(0x80));
			api.createFunction(api.toAddr(0x80), "_main");
		} catch (LockException | IllegalArgumentException | MemoryConflictException | AddressOverflowException
				| CancelledException | AddressOutOfBoundsException | MemoryAccessException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		return super.validateOptions(provider, loadSpec, options, program);
	}
}
