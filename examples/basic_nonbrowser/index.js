import namedrop from '../../index.js';

//namedrop.setApiUri('https://anderspitman.com/namedrop'); 

const client = new namedrop.Client({
  token: '<token-here>',
  domain: 'anderspitman.com',
  host: 'test',
});

const records = await client.getRecords();
console.log(records);

try {
  await client.setRecords({
    records: [
      {
        type: 'CNAME',
        value: 'takingnames.io',
      },
    ],
  });
}
catch (e) {
  console.error(e);
}
