// dataPlans.js
const datas = require('./myjs.json'); // or use import datas from './myjs.json' if using ESM

// Export each network plan
const MTN_PLAN = datas.MTN_PLAN;
const GLO_PLAN = datas.GLO_PLAN;
const AIRTEL_PLAN = datas.AIRTEL_PLAN;
const MOBILE9_PLAN = datas["9MOBILE_PLAN"]; // 9MOBILE_PLAN key has number at start

// Map for easy lookup
const DATA_PLANS = {
  1: MTN_PLAN.ALL,
  2: AIRTEL_PLAN.ALL,
  3: GLO_PLAN.ALL,
  4: MOBILE9_PLAN.ALL
};

module.exports = { MTN_PLAN, GLO_PLAN, AIRTEL_PLAN, MOBILE9_PLAN, DATA_PLANS };
