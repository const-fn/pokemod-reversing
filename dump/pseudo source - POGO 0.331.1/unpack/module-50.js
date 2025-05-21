import "@pkmd/console";
import "./main/utils/Patches";
import {
  startKamiThread,
  waitUntilLoaded,
  getModulesToEnable,
  loadModules,
} from "./loader";
import "./main/utils/Common";
import "./main/utils/PgpUtils";
import "./tiers";
const __importDefault = (mod) =>
  mod && mod.__esModule ? mod : { default: mod };
setConsoleFlags({ threads: true, logLevel: "unsafe" });
info("Starting HAL Agent");
const ditto_1 = __importDefault(require("@pkmd/ditto"));
const UserData_1 = __importDefault(require("./main/utils/UserData"));
const HappyBdHanke_1 = __importDefault(
  require("./development/WIPs/HappyBdHanke")
);
startKamiThread();

rpc.exports = {
  init(stage, parameters) {
    const selectedModules = parameters.modules || [];
    waitUntilLoaded(() => {
      let _parameters$uuid;
      const startGlobalTime = Date.now();
      ditto_1.default.initialize();
      ditto_1.default.Telemetry.userData = UserData_1.default;

      ditto_1.default.Telemetry._identity =
        null == (_parameters$uuid = parameters.uuid)
          ? ditto_1.default.Telemetry._identity
          : _parameters$uuid;

      const modulesToEnable = getModulesToEnable(
        selectedModules,
        UserData_1.default,
        false
      );
      modulesToEnable.push(HappyBdHanke_1.default);
      loadModules(modulesToEnable, startGlobalTime);
    });
  },
};
