pragma circom 2.1.5;

include "@zk-email/zk-regex-circom/circuits/regex_helpers.circom";

// regex: (\r\n|^)from:[^\r\n]+\r\n
template FromAllRegex(msg_bytes) {
	signal input msg[msg_bytes];
	signal output out;

	var num_bytes = msg_bytes+1;
	signal in[num_bytes];
	in[0]<==255;
	for (var i = 0; i < msg_bytes; i++) {
		in[i+1] <== msg[i];
	}

	component eq[56][num_bytes];
	component lt[12][num_bytes];
	component and[39][num_bytes];
	component multi_or[12][num_bytes];
	signal states[num_bytes+1][18];
	signal states_tmp[num_bytes+1][18];
	signal from_zero_enabled[num_bytes+1];
	from_zero_enabled[num_bytes] <== 0;
	component state_changed[num_bytes];

	for (var i = 1; i < 18; i++) {
		states[0][i] <== 0;
	}

	for (var i = 0; i < num_bytes; i++) {
		state_changed[i] = MultiOR(17);
		states[i][0] <== 1;
		eq[0][i] = IsEqual();
		eq[0][i].in[0] <== in[i];
		eq[0][i].in[1] <== 13;
		and[0][i] = AND();
		and[0][i].a <== states[i][0];
		and[0][i].b <== eq[0][i].out;
		states_tmp[i+1][1] <== 0;
		eq[1][i] = IsEqual();
		eq[1][i].in[0] <== in[i];
		eq[1][i].in[1] <== 255;
		and[1][i] = AND();
		and[1][i].a <== states[i][0];
		and[1][i].b <== eq[1][i].out;
		eq[2][i] = IsEqual();
		eq[2][i].in[0] <== in[i];
		eq[2][i].in[1] <== 10;
		and[2][i] = AND();
		and[2][i].a <== states[i][1];
		and[2][i].b <== eq[2][i].out;
		states_tmp[i+1][2] <== and[2][i].out;
		eq[3][i] = IsEqual();
		eq[3][i].in[0] <== in[i];
		eq[3][i].in[1] <== 102;
		and[3][i] = AND();
		and[3][i].a <== states[i][2];
		and[3][i].b <== eq[3][i].out;
		states[i+1][3] <== and[3][i].out;
		eq[4][i] = IsEqual();
		eq[4][i].in[0] <== in[i];
		eq[4][i].in[1] <== 114;
		and[4][i] = AND();
		and[4][i].a <== states[i][3];
		and[4][i].b <== eq[4][i].out;
		states[i+1][4] <== and[4][i].out;
		eq[5][i] = IsEqual();
		eq[5][i].in[0] <== in[i];
		eq[5][i].in[1] <== 111;
		and[5][i] = AND();
		and[5][i].a <== states[i][4];
		and[5][i].b <== eq[5][i].out;
		states[i+1][5] <== and[5][i].out;
		eq[6][i] = IsEqual();
		eq[6][i].in[0] <== in[i];
		eq[6][i].in[1] <== 109;
		and[6][i] = AND();
		and[6][i].a <== states[i][5];
		and[6][i].b <== eq[6][i].out;
		states[i+1][6] <== and[6][i].out;
		eq[7][i] = IsEqual();
		eq[7][i].in[0] <== in[i];
		eq[7][i].in[1] <== 58;
		and[7][i] = AND();
		and[7][i].a <== states[i][6];
		and[7][i].b <== eq[7][i].out;
		states[i+1][7] <== and[7][i].out;
		lt[0][i] = LessEqThan(8);
		lt[0][i].in[0] <== 14;
		lt[0][i].in[1] <== in[i];
		lt[1][i] = LessEqThan(8);
		lt[1][i].in[0] <== in[i];
		lt[1][i].in[1] <== 127;
		and[8][i] = AND();
		and[8][i].a <== lt[0][i].out;
		and[8][i].b <== lt[1][i].out;
		eq[8][i] = IsEqual();
		eq[8][i].in[0] <== in[i];
		eq[8][i].in[1] <== 1;
		eq[9][i] = IsEqual();
		eq[9][i].in[0] <== in[i];
		eq[9][i].in[1] <== 2;
		eq[10][i] = IsEqual();
		eq[10][i].in[0] <== in[i];
		eq[10][i].in[1] <== 3;
		eq[11][i] = IsEqual();
		eq[11][i].in[0] <== in[i];
		eq[11][i].in[1] <== 4;
		eq[12][i] = IsEqual();
		eq[12][i].in[0] <== in[i];
		eq[12][i].in[1] <== 5;
		eq[13][i] = IsEqual();
		eq[13][i].in[0] <== in[i];
		eq[13][i].in[1] <== 6;
		eq[14][i] = IsEqual();
		eq[14][i].in[0] <== in[i];
		eq[14][i].in[1] <== 7;
		eq[15][i] = IsEqual();
		eq[15][i].in[0] <== in[i];
		eq[15][i].in[1] <== 8;
		eq[16][i] = IsEqual();
		eq[16][i].in[0] <== in[i];
		eq[16][i].in[1] <== 9;
		eq[17][i] = IsEqual();
		eq[17][i].in[0] <== in[i];
		eq[17][i].in[1] <== 11;
		eq[18][i] = IsEqual();
		eq[18][i].in[0] <== in[i];
		eq[18][i].in[1] <== 12;
		and[9][i] = AND();
		and[9][i].a <== states[i][7];
		multi_or[0][i] = MultiOR(12);
		multi_or[0][i].in[0] <== and[8][i].out;
		multi_or[0][i].in[1] <== eq[8][i].out;
		multi_or[0][i].in[2] <== eq[9][i].out;
		multi_or[0][i].in[3] <== eq[10][i].out;
		multi_or[0][i].in[4] <== eq[11][i].out;
		multi_or[0][i].in[5] <== eq[12][i].out;
		multi_or[0][i].in[6] <== eq[13][i].out;
		multi_or[0][i].in[7] <== eq[14][i].out;
		multi_or[0][i].in[8] <== eq[15][i].out;
		multi_or[0][i].in[9] <== eq[16][i].out;
		multi_or[0][i].in[10] <== eq[17][i].out;
		multi_or[0][i].in[11] <== eq[18][i].out;
		and[9][i].b <== multi_or[0][i].out;
		and[10][i] = AND();
		and[10][i].a <== states[i][8];
		and[10][i].b <== multi_or[0][i].out;
		lt[2][i] = LessEqThan(8);
		lt[2][i].in[0] <== 128;
		lt[2][i].in[1] <== in[i];
		lt[3][i] = LessEqThan(8);
		lt[3][i].in[0] <== in[i];
		lt[3][i].in[1] <== 191;
		and[11][i] = AND();
		and[11][i].a <== lt[2][i].out;
		and[11][i].b <== lt[3][i].out;
		and[12][i] = AND();
		and[12][i].a <== states[i][9];
		and[12][i].b <== and[11][i].out;
		multi_or[1][i] = MultiOR(3);
		multi_or[1][i].in[0] <== and[9][i].out;
		multi_or[1][i].in[1] <== and[10][i].out;
		multi_or[1][i].in[2] <== and[12][i].out;
		states[i+1][8] <== multi_or[1][i].out;
		lt[4][i] = LessEqThan(8);
		lt[4][i].in[0] <== 194;
		lt[4][i].in[1] <== in[i];
		lt[5][i] = LessEqThan(8);
		lt[5][i].in[0] <== in[i];
		lt[5][i].in[1] <== 223;
		and[13][i] = AND();
		and[13][i].a <== lt[4][i].out;
		and[13][i].b <== lt[5][i].out;
		and[14][i] = AND();
		and[14][i].a <== states[i][7];
		and[14][i].b <== and[13][i].out;
		and[15][i] = AND();
		and[15][i].a <== states[i][8];
		and[15][i].b <== and[13][i].out;
		lt[6][i] = LessEqThan(8);
		lt[6][i].in[0] <== 160;
		lt[6][i].in[1] <== in[i];
		lt[7][i] = LessEqThan(8);
		lt[7][i].in[0] <== in[i];
		lt[7][i].in[1] <== 191;
		and[16][i] = AND();
		and[16][i].a <== lt[6][i].out;
		and[16][i].b <== lt[7][i].out;
		and[17][i] = AND();
		and[17][i].a <== states[i][10];
		and[17][i].b <== and[16][i].out;
		and[18][i] = AND();
		and[18][i].a <== states[i][11];
		and[18][i].b <== and[11][i].out;
		lt[8][i] = LessEqThan(8);
		lt[8][i].in[0] <== 128;
		lt[8][i].in[1] <== in[i];
		lt[9][i] = LessEqThan(8);
		lt[9][i].in[0] <== in[i];
		lt[9][i].in[1] <== 159;
		and[19][i] = AND();
		and[19][i].a <== lt[8][i].out;
		and[19][i].b <== lt[9][i].out;
		and[20][i] = AND();
		and[20][i].a <== states[i][12];
		and[20][i].b <== and[19][i].out;
		multi_or[2][i] = MultiOR(5);
		multi_or[2][i].in[0] <== and[14][i].out;
		multi_or[2][i].in[1] <== and[15][i].out;
		multi_or[2][i].in[2] <== and[17][i].out;
		multi_or[2][i].in[3] <== and[18][i].out;
		multi_or[2][i].in[4] <== and[20][i].out;
		states[i+1][9] <== multi_or[2][i].out;
		eq[19][i] = IsEqual();
		eq[19][i].in[0] <== in[i];
		eq[19][i].in[1] <== 224;
		and[21][i] = AND();
		and[21][i].a <== states[i][7];
		and[21][i].b <== eq[19][i].out;
		and[22][i] = AND();
		and[22][i].a <== states[i][8];
		and[22][i].b <== eq[19][i].out;
		multi_or[3][i] = MultiOR(2);
		multi_or[3][i].in[0] <== and[21][i].out;
		multi_or[3][i].in[1] <== and[22][i].out;
		states[i+1][10] <== multi_or[3][i].out;
		eq[20][i] = IsEqual();
		eq[20][i].in[0] <== in[i];
		eq[20][i].in[1] <== 225;
		eq[21][i] = IsEqual();
		eq[21][i].in[0] <== in[i];
		eq[21][i].in[1] <== 226;
		eq[22][i] = IsEqual();
		eq[22][i].in[0] <== in[i];
		eq[22][i].in[1] <== 227;
		eq[23][i] = IsEqual();
		eq[23][i].in[0] <== in[i];
		eq[23][i].in[1] <== 228;
		eq[24][i] = IsEqual();
		eq[24][i].in[0] <== in[i];
		eq[24][i].in[1] <== 229;
		eq[25][i] = IsEqual();
		eq[25][i].in[0] <== in[i];
		eq[25][i].in[1] <== 230;
		eq[26][i] = IsEqual();
		eq[26][i].in[0] <== in[i];
		eq[26][i].in[1] <== 231;
		eq[27][i] = IsEqual();
		eq[27][i].in[0] <== in[i];
		eq[27][i].in[1] <== 232;
		eq[28][i] = IsEqual();
		eq[28][i].in[0] <== in[i];
		eq[28][i].in[1] <== 233;
		eq[29][i] = IsEqual();
		eq[29][i].in[0] <== in[i];
		eq[29][i].in[1] <== 234;
		eq[30][i] = IsEqual();
		eq[30][i].in[0] <== in[i];
		eq[30][i].in[1] <== 235;
		eq[31][i] = IsEqual();
		eq[31][i].in[0] <== in[i];
		eq[31][i].in[1] <== 236;
		eq[32][i] = IsEqual();
		eq[32][i].in[0] <== in[i];
		eq[32][i].in[1] <== 238;
		eq[33][i] = IsEqual();
		eq[33][i].in[0] <== in[i];
		eq[33][i].in[1] <== 239;
		and[23][i] = AND();
		and[23][i].a <== states[i][7];
		multi_or[4][i] = MultiOR(14);
		multi_or[4][i].in[0] <== eq[20][i].out;
		multi_or[4][i].in[1] <== eq[21][i].out;
		multi_or[4][i].in[2] <== eq[22][i].out;
		multi_or[4][i].in[3] <== eq[23][i].out;
		multi_or[4][i].in[4] <== eq[24][i].out;
		multi_or[4][i].in[5] <== eq[25][i].out;
		multi_or[4][i].in[6] <== eq[26][i].out;
		multi_or[4][i].in[7] <== eq[27][i].out;
		multi_or[4][i].in[8] <== eq[28][i].out;
		multi_or[4][i].in[9] <== eq[29][i].out;
		multi_or[4][i].in[10] <== eq[30][i].out;
		multi_or[4][i].in[11] <== eq[31][i].out;
		multi_or[4][i].in[12] <== eq[32][i].out;
		multi_or[4][i].in[13] <== eq[33][i].out;
		and[23][i].b <== multi_or[4][i].out;
		and[24][i] = AND();
		and[24][i].a <== states[i][8];
		and[24][i].b <== multi_or[4][i].out;
		lt[10][i] = LessEqThan(8);
		lt[10][i].in[0] <== 144;
		lt[10][i].in[1] <== in[i];
		lt[11][i] = LessEqThan(8);
		lt[11][i].in[0] <== in[i];
		lt[11][i].in[1] <== 191;
		and[25][i] = AND();
		and[25][i].a <== lt[10][i].out;
		and[25][i].b <== lt[11][i].out;
		and[26][i] = AND();
		and[26][i].a <== states[i][13];
		and[26][i].b <== and[25][i].out;
		and[27][i] = AND();
		and[27][i].a <== states[i][14];
		and[27][i].b <== and[11][i].out;
		eq[34][i] = IsEqual();
		eq[34][i].in[0] <== in[i];
		eq[34][i].in[1] <== 128;
		eq[35][i] = IsEqual();
		eq[35][i].in[0] <== in[i];
		eq[35][i].in[1] <== 129;
		eq[36][i] = IsEqual();
		eq[36][i].in[0] <== in[i];
		eq[36][i].in[1] <== 130;
		eq[37][i] = IsEqual();
		eq[37][i].in[0] <== in[i];
		eq[37][i].in[1] <== 131;
		eq[38][i] = IsEqual();
		eq[38][i].in[0] <== in[i];
		eq[38][i].in[1] <== 132;
		eq[39][i] = IsEqual();
		eq[39][i].in[0] <== in[i];
		eq[39][i].in[1] <== 133;
		eq[40][i] = IsEqual();
		eq[40][i].in[0] <== in[i];
		eq[40][i].in[1] <== 134;
		eq[41][i] = IsEqual();
		eq[41][i].in[0] <== in[i];
		eq[41][i].in[1] <== 135;
		eq[42][i] = IsEqual();
		eq[42][i].in[0] <== in[i];
		eq[42][i].in[1] <== 136;
		eq[43][i] = IsEqual();
		eq[43][i].in[0] <== in[i];
		eq[43][i].in[1] <== 137;
		eq[44][i] = IsEqual();
		eq[44][i].in[0] <== in[i];
		eq[44][i].in[1] <== 138;
		eq[45][i] = IsEqual();
		eq[45][i].in[0] <== in[i];
		eq[45][i].in[1] <== 139;
		eq[46][i] = IsEqual();
		eq[46][i].in[0] <== in[i];
		eq[46][i].in[1] <== 140;
		eq[47][i] = IsEqual();
		eq[47][i].in[0] <== in[i];
		eq[47][i].in[1] <== 141;
		eq[48][i] = IsEqual();
		eq[48][i].in[0] <== in[i];
		eq[48][i].in[1] <== 142;
		eq[49][i] = IsEqual();
		eq[49][i].in[0] <== in[i];
		eq[49][i].in[1] <== 143;
		and[28][i] = AND();
		and[28][i].a <== states[i][15];
		multi_or[5][i] = MultiOR(16);
		multi_or[5][i].in[0] <== eq[34][i].out;
		multi_or[5][i].in[1] <== eq[35][i].out;
		multi_or[5][i].in[2] <== eq[36][i].out;
		multi_or[5][i].in[3] <== eq[37][i].out;
		multi_or[5][i].in[4] <== eq[38][i].out;
		multi_or[5][i].in[5] <== eq[39][i].out;
		multi_or[5][i].in[6] <== eq[40][i].out;
		multi_or[5][i].in[7] <== eq[41][i].out;
		multi_or[5][i].in[8] <== eq[42][i].out;
		multi_or[5][i].in[9] <== eq[43][i].out;
		multi_or[5][i].in[10] <== eq[44][i].out;
		multi_or[5][i].in[11] <== eq[45][i].out;
		multi_or[5][i].in[12] <== eq[46][i].out;
		multi_or[5][i].in[13] <== eq[47][i].out;
		multi_or[5][i].in[14] <== eq[48][i].out;
		multi_or[5][i].in[15] <== eq[49][i].out;
		and[28][i].b <== multi_or[5][i].out;
		multi_or[6][i] = MultiOR(5);
		multi_or[6][i].in[0] <== and[23][i].out;
		multi_or[6][i].in[1] <== and[24][i].out;
		multi_or[6][i].in[2] <== and[26][i].out;
		multi_or[6][i].in[3] <== and[27][i].out;
		multi_or[6][i].in[4] <== and[28][i].out;
		states[i+1][11] <== multi_or[6][i].out;
		eq[50][i] = IsEqual();
		eq[50][i].in[0] <== in[i];
		eq[50][i].in[1] <== 237;
		and[29][i] = AND();
		and[29][i].a <== states[i][7];
		and[29][i].b <== eq[50][i].out;
		and[30][i] = AND();
		and[30][i].a <== states[i][8];
		and[30][i].b <== eq[50][i].out;
		multi_or[7][i] = MultiOR(2);
		multi_or[7][i].in[0] <== and[29][i].out;
		multi_or[7][i].in[1] <== and[30][i].out;
		states[i+1][12] <== multi_or[7][i].out;
		eq[51][i] = IsEqual();
		eq[51][i].in[0] <== in[i];
		eq[51][i].in[1] <== 240;
		and[31][i] = AND();
		and[31][i].a <== states[i][7];
		and[31][i].b <== eq[51][i].out;
		and[32][i] = AND();
		and[32][i].a <== states[i][8];
		and[32][i].b <== eq[51][i].out;
		multi_or[8][i] = MultiOR(2);
		multi_or[8][i].in[0] <== and[31][i].out;
		multi_or[8][i].in[1] <== and[32][i].out;
		states[i+1][13] <== multi_or[8][i].out;
		eq[52][i] = IsEqual();
		eq[52][i].in[0] <== in[i];
		eq[52][i].in[1] <== 241;
		eq[53][i] = IsEqual();
		eq[53][i].in[0] <== in[i];
		eq[53][i].in[1] <== 242;
		eq[54][i] = IsEqual();
		eq[54][i].in[0] <== in[i];
		eq[54][i].in[1] <== 243;
		and[33][i] = AND();
		and[33][i].a <== states[i][7];
		multi_or[9][i] = MultiOR(3);
		multi_or[9][i].in[0] <== eq[52][i].out;
		multi_or[9][i].in[1] <== eq[53][i].out;
		multi_or[9][i].in[2] <== eq[54][i].out;
		and[33][i].b <== multi_or[9][i].out;
		and[34][i] = AND();
		and[34][i].a <== states[i][8];
		and[34][i].b <== multi_or[9][i].out;
		multi_or[10][i] = MultiOR(2);
		multi_or[10][i].in[0] <== and[33][i].out;
		multi_or[10][i].in[1] <== and[34][i].out;
		states[i+1][14] <== multi_or[10][i].out;
		eq[55][i] = IsEqual();
		eq[55][i].in[0] <== in[i];
		eq[55][i].in[1] <== 244;
		and[35][i] = AND();
		and[35][i].a <== states[i][7];
		and[35][i].b <== eq[55][i].out;
		and[36][i] = AND();
		and[36][i].a <== states[i][8];
		and[36][i].b <== eq[55][i].out;
		multi_or[11][i] = MultiOR(2);
		multi_or[11][i].in[0] <== and[35][i].out;
		multi_or[11][i].in[1] <== and[36][i].out;
		states[i+1][15] <== multi_or[11][i].out;
		and[37][i] = AND();
		and[37][i].a <== states[i][8];
		and[37][i].b <== eq[0][i].out;
		states[i+1][16] <== and[37][i].out;
		and[38][i] = AND();
		and[38][i].a <== states[i][16];
		and[38][i].b <== eq[2][i].out;
		states[i+1][17] <== and[38][i].out;
		from_zero_enabled[i] <== MultiNOR(17)([states_tmp[i+1][1], states_tmp[i+1][2], states[i+1][3], states[i+1][4], states[i+1][5], states[i+1][6], states[i+1][7], states[i+1][8], states[i+1][9], states[i+1][10], states[i+1][11], states[i+1][12], states[i+1][13], states[i+1][14], states[i+1][15], states[i+1][16], states[i+1][17]]);
		states[i+1][1] <== MultiOR(2)([states_tmp[i+1][1], from_zero_enabled[i] * and[0][i].out]);
		states[i+1][2] <== MultiOR(2)([states_tmp[i+1][2], from_zero_enabled[i] * and[1][i].out]);
		state_changed[i].in[0] <== states[i+1][1];
		state_changed[i].in[1] <== states[i+1][2];
		state_changed[i].in[2] <== states[i+1][3];
		state_changed[i].in[3] <== states[i+1][4];
		state_changed[i].in[4] <== states[i+1][5];
		state_changed[i].in[5] <== states[i+1][6];
		state_changed[i].in[6] <== states[i+1][7];
		state_changed[i].in[7] <== states[i+1][8];
		state_changed[i].in[8] <== states[i+1][9];
		state_changed[i].in[9] <== states[i+1][10];
		state_changed[i].in[10] <== states[i+1][11];
		state_changed[i].in[11] <== states[i+1][12];
		state_changed[i].in[12] <== states[i+1][13];
		state_changed[i].in[13] <== states[i+1][14];
		state_changed[i].in[14] <== states[i+1][15];
		state_changed[i].in[15] <== states[i+1][16];
		state_changed[i].in[16] <== states[i+1][17];
	}

	component is_accepted = MultiOR(num_bytes+1);
	for (var i = 0; i <= num_bytes; i++) {
		is_accepted.in[i] <== states[i][17];
	}
	out <== is_accepted.out;
	signal is_consecutive[msg_bytes+1][3];
	is_consecutive[msg_bytes][2] <== 0;
	for (var i = 0; i < msg_bytes; i++) {
		is_consecutive[msg_bytes-1-i][0] <== states[num_bytes-i][17] * (1 - is_consecutive[msg_bytes-i][2]) + is_consecutive[msg_bytes-i][2];
		is_consecutive[msg_bytes-1-i][1] <== state_changed[msg_bytes-i].out * is_consecutive[msg_bytes-1-i][0];
		is_consecutive[msg_bytes-1-i][2] <== ORAnd()([(1 - from_zero_enabled[msg_bytes-i+1]), states[num_bytes-i][17], is_consecutive[msg_bytes-1-i][1]]);
	}
	// substrings calculated: [{(7, 8), (7, 9), (7, 10), (7, 11), (7, 12), (7, 13), (7, 14), (7, 15), (8, 8), (8, 9), (8, 10), (8, 11), (8, 12), (8, 13), (8, 14), (8, 15), (9, 8), (10, 9), (11, 9), (12, 9), (13, 11), (14, 11), (15, 11)}]
	signal prev_states0[23][msg_bytes];
	signal is_substr0[msg_bytes];
	signal is_reveal0[msg_bytes];
	signal output reveal0[msg_bytes];
	for (var i = 0; i < msg_bytes; i++) {
		 // the 0-th substring transitions: [(7, 8), (7, 9), (7, 10), (7, 11), (7, 12), (7, 13), (7, 14), (7, 15), (8, 8), (8, 9), (8, 10), (8, 11), (8, 12), (8, 13), (8, 14), (8, 15), (9, 8), (10, 9), (11, 9), (12, 9), (13, 11), (14, 11), (15, 11)]
		prev_states0[0][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][7];
		prev_states0[1][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][7];
		prev_states0[2][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][7];
		prev_states0[3][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][7];
		prev_states0[4][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][7];
		prev_states0[5][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][7];
		prev_states0[6][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][7];
		prev_states0[7][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][7];
		prev_states0[8][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][8];
		prev_states0[9][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][8];
		prev_states0[10][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][8];
		prev_states0[11][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][8];
		prev_states0[12][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][8];
		prev_states0[13][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][8];
		prev_states0[14][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][8];
		prev_states0[15][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][8];
		prev_states0[16][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][9];
		prev_states0[17][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][10];
		prev_states0[18][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][11];
		prev_states0[19][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][12];
		prev_states0[20][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][13];
		prev_states0[21][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][14];
		prev_states0[22][i] <== (1 - from_zero_enabled[i+1]) * states[i+1][15];
		is_substr0[i] <== MultiOR(23)([prev_states0[0][i] * states[i+2][8], prev_states0[1][i] * states[i+2][9], prev_states0[2][i] * states[i+2][10], prev_states0[3][i] * states[i+2][11], prev_states0[4][i] * states[i+2][12], prev_states0[5][i] * states[i+2][13], prev_states0[6][i] * states[i+2][14], prev_states0[7][i] * states[i+2][15], prev_states0[8][i] * states[i+2][8], prev_states0[9][i] * states[i+2][9], prev_states0[10][i] * states[i+2][10], prev_states0[11][i] * states[i+2][11], prev_states0[12][i] * states[i+2][12], prev_states0[13][i] * states[i+2][13], prev_states0[14][i] * states[i+2][14], prev_states0[15][i] * states[i+2][15], prev_states0[16][i] * states[i+2][8], prev_states0[17][i] * states[i+2][9], prev_states0[18][i] * states[i+2][9], prev_states0[19][i] * states[i+2][9], prev_states0[20][i] * states[i+2][11], prev_states0[21][i] * states[i+2][11], prev_states0[22][i] * states[i+2][11]]);
		is_reveal0[i] <== MultiAND(3)([out, is_substr0[i], is_consecutive[i][2]]);
		reveal0[i] <== in[i+1] * is_reveal0[i];
	}
}