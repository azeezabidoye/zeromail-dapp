import { task } from "hardhat/config";
import { HardhatRuntimeEnvironment } from "hardhat/types";
import { saveDeployment } from "./utils";

// Task to deploy the Counter contract
task(
  "deploy-counter",
  "Deploy the Counter contract to the selected network",
).setAction(async (_, hre: HardhatRuntimeEnvironment) => {
  const { ethers, network } = hre;
});
