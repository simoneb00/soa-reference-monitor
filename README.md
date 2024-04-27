# Kernel Level Reference Monitor for File Protection 

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#project-specification">Project Specification</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#installation">Installation</a></li>
        <li><a href="#main-features">Main Features</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
  </ol>
</details>


## About The Project

This project was developed as part of the Advanced Operating Systems course at the University of Rome Tor Vergata.

## Project Specification

This specification is related to a Linux Kernel Module (LKM) implementing a reference monitor for file protection. The reference monitor can be in one of the following four states:

* OFF, meaning that its operations are currently disabled;
* ON, meaning that its operations are currently enabled;
* REC-ON/REC-OFF, meaning that it can be currently reconfigured (in either ON or OFF mode). 

The configuration of the reference monitor is based on a set of file system paths. Each path corresponds to a file/dir that cannot be currently opened in write mode. Hence, any attempt to write-open the path needs to return an error, independently of the user-id that attempts the open operation.

Reconfiguring the reference monitor means that some path to be protected can be added/removed. In any case, changing the current state of the reference monitor requires that the thread that is running this operation needs to be marked with effective-user-id set to root, and additionally the reconfiguration requires in input a password that is reference-monitor specific. This means that the encrypted version of the password is maintained at the level of the reference monitor architecture for performing the required checks.

It is up to the software designer to determine if the above states ON/OFF/REC-ON/REC-OFF can be changed via VFS API or via specific system-calls. The same is true for the services that implement each reconfiguration step (addition/deletion of paths to be checked). Together with kernel level stuff, the project should also deliver user space code/commands for invoking the system level API with correct parameters.

In addition to the above specifics, the project should also include the realization of a file system where a single append-only file should record the following tuple of data (per line of the file) each time an attempt to write-open a protected file system path is attempted:

* the process TGID
* the thread ID
* the user-id
* the effective user-id
* the program path-name that is currently attempting the open
* a cryptographic hash of the program file content 

The the computation of the cryptographic hash and the writing of the above tuple should be carried in deferred work. 

## Getting Started

### Installation
1. Clone the repo
   ```sh
   git clone https://github.com/simoneb00/soa-reference-monitor.git
   ```
2. Enter directory `soa-reference-monitor` and build the project
   ```sh
   make
   ```
3. Install the module (in this phase, the user is asked to set the reference monitor password) 
   ```sh
   sudo make mount
   ```
### Main Features
When the module is installed into the kernel, its state is set to OFF (0), so its operations are initially disabled. When the reference monitor is set to one of the reconfiguration states (see section <a href="#usage">Usage</a>), the user can specify files/directories to be blacklisted. Once a file/directory is blacklisted - and the reference monitor is on - the following operations on it are blocked:
* **Write-openings** (in the case of files, also on sym/hard links to blacklisted files);
* **Files/subdirectories creation** (in the case of directories);
* **Deletion/unlinkage**;
* **Renaming**: this also implies that a blacklisted file/directory cannot be **moved** to another location;
* Creation of **symbolic links**;
* Creation of **hard links**;

The log file path is `/mnt/ref-monitor-fs/ref-monitor-log.txt`.

## Usage
The following commands are available to manage the reference monitor:
* ```sh
  switch_state state
  ```
  Change the reference monitor state. The parameter `state` can be one of the following:
  * 0 (OFF),
  * 1 (ON),
  * 2 (REC-OFF)
  * 3 (REC-ON)
    
  This command requires sudo privileges and, if the target state is REC-OFF/REC-ON, it also requires the reference monitor password.
* ```sh
  add_to_blacklist file
  ```
  Add a file/directory to the blacklist.\
  This command requires the reference monitor to be on a reconfiguration state.
* ```sh
  print_blacklist
  ```
  Print the files/directories blacklist.
* ```sh
  remove_from_blacklist file mode
  ```
  Remove a file/directory from the blacklist.\
  The parameter `mode` can be one of the following:
  * 0 (DELETE_DIRS_ONLY): only the specified directory (and its eventual subdirectories) will be removed from the blacklist. This enables the possibility to create some files/subdirectories inside a blacklisted directory, without whitelisting its whole content.
  * 1 (DELETE_ALL): the specified directory and all its content will be removed from the blacklist.
  
  `mode` is only evaluated in the case of directories, and ignored in the case of files (although it must still be specified).
